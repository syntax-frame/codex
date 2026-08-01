use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

const COMPRESSED_SUFFIX: &str = ".zst";
const MAX_NOT_FOUND_RETRIES: usize = 3;
const OPEN_RETRY_DELAY: Duration = Duration::from_millis(50);

/// A single JSONL record may contain a persisted 50 MiB audio input, whose
/// base64 representation is roughly 67 MiB before JSON framing. Keep enough
/// headroom for that legitimate envelope without allowing unbounded growth.
pub const MAX_ROLLOUT_RECORD_BYTES: usize = 96 * 1024 * 1024;

/// Long conversations remain resumable while decoded compressed data is kept
/// within a predictable mobile-memory envelope.
pub const MAX_ROLLOUT_DECODED_BYTES: usize = 256 * 1024 * 1024;

/// The decoded-byte limit normally wins first; this separate bound prevents a
/// pathological number of tiny records from growing the item vector forever.
pub const MAX_ROLLOUT_RECORDS: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RolloutReadResource {
    RecordBuffer,
    ItemList,
}

impl fmt::Display for RolloutReadResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordBuffer => formatter.write_str("record buffer"),
            Self::ItemList => formatter.write_str("item list"),
        }
    }
}

/// Content-free, non-mutating rollout read failures.
///
/// The variants deliberately include only structural ordinals and byte limits.
/// They never retain record contents, paths, credentials, or serde diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RolloutReadError {
    ResourceExhausted {
        resource: RolloutReadResource,
        record: usize,
    },
    RecordTooLarge {
        record: usize,
        limit: usize,
    },
    DecodedBytesTooLarge {
        limit: usize,
    },
    TooManyRecords {
        limit: usize,
    },
    TruncatedRecord {
        record: usize,
    },
    InvalidUtf8 {
        record: usize,
    },
    MalformedJson {
        record: usize,
    },
    CompressedData {
        record: usize,
    },
    EmptySession,
    WorkerFailed,
}

impl fmt::Display for RolloutReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceExhausted { resource, record } => {
                write!(
                    formatter,
                    "rollout resource exhausted for {resource} at record {record}"
                )
            }
            Self::RecordTooLarge { record, limit } => {
                write!(
                    formatter,
                    "rollout record {record} exceeds the {limit}-byte limit"
                )
            }
            Self::DecodedBytesTooLarge { limit } => {
                write!(
                    formatter,
                    "rollout exceeds the {limit}-byte decoded-data limit"
                )
            }
            Self::TooManyRecords { limit } => {
                write!(formatter, "rollout exceeds the {limit}-record limit")
            }
            Self::TruncatedRecord { record } => {
                write!(formatter, "rollout record {record} is truncated")
            }
            Self::InvalidUtf8 { record } => {
                write!(formatter, "rollout record {record} is not valid UTF-8")
            }
            Self::MalformedJson { record } => {
                write!(formatter, "rollout record {record} is malformed JSON")
            }
            Self::CompressedData { record } => {
                write!(
                    formatter,
                    "compressed rollout data is malformed near record {record}"
                )
            }
            Self::EmptySession => formatter.write_str("rollout contains no session records"),
            Self::WorkerFailed => formatter.write_str("rollout read worker failed"),
        }
    }
}

impl Error for RolloutReadError {}

pub fn rollout_read_error(error: &io::Error) -> Option<&RolloutReadError> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RolloutReadError>())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RolloutReadLimits {
    pub(crate) max_record_bytes: usize,
    pub(crate) max_decoded_bytes: usize,
    pub(crate) max_records: usize,
}

impl Default for RolloutReadLimits {
    fn default() -> Self {
        Self {
            max_record_bytes: MAX_ROLLOUT_RECORD_BYTES,
            max_decoded_bytes: MAX_ROLLOUT_DECODED_BYTES,
            max_records: MAX_ROLLOUT_RECORDS,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RolloutRecord {
    pub(crate) ordinal: usize,
    pub(crate) line: String,
    pub(crate) newline_terminated: bool,
}

pub(crate) struct BoundedRolloutReader {
    reader: Box<dyn BufRead + Send>,
    limits: RolloutReadLimits,
    decoded_bytes: usize,
    records: usize,
    compressed: bool,
}

impl BoundedRolloutReader {
    pub(crate) fn open(path: &Path, limits: RolloutReadLimits) -> io::Result<Self> {
        let compressed = is_compressed_rollout_path(path);
        let reader: Box<dyn BufRead + Send> = if compressed {
            let input = File::open(path)?;
            let decoder = zstd::stream::read::Decoder::new(input)
                .map_err(|_| typed_error(RolloutReadError::CompressedData { record: 1 }))?;
            Box::new(io::BufReader::new(decoder))
        } else {
            Box::new(io::BufReader::new(File::open(path)?))
        };
        Ok(Self {
            reader,
            limits,
            decoded_bytes: 0,
            records: 0,
            compressed,
        })
    }

    pub(crate) fn open_with_retry(
        requested_path: &Path,
        limits: RolloutReadLimits,
    ) -> io::Result<Self> {
        for attempt in 0..=MAX_NOT_FOUND_RETRIES {
            let physical_path = existing_rollout_path(requested_path)
                .unwrap_or_else(|| requested_path.to_path_buf());
            match Self::open(physical_path.as_path(), limits) {
                Ok(reader) => return Ok(reader),
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        && attempt < MAX_NOT_FOUND_RETRIES =>
                {
                    std::thread::sleep(OPEN_RETRY_DELAY);
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("rollout open retry loop always returns")
    }

    pub(crate) fn next_record(&mut self) -> io::Result<Option<RolloutRecord>> {
        let ordinal = self.records.checked_add(1).ok_or_else(|| {
            typed_error(RolloutReadError::TooManyRecords {
                limit: self.limits.max_records,
            })
        })?;

        let mut record = Vec::new();
        loop {
            let (consumed, decoded_bytes, found_newline) = {
                let available = self.reader.fill_buf().map_err(|error| {
                    if self.compressed {
                        typed_error(RolloutReadError::CompressedData { record: ordinal })
                    } else {
                        error
                    }
                })?;
                if available.is_empty() {
                    if record.is_empty() {
                        return Ok(None);
                    }
                    return self.finish_record(ordinal, record, false).map(Some);
                }
                if record.is_empty() && ordinal > self.limits.max_records {
                    return Err(typed_error(RolloutReadError::TooManyRecords {
                        limit: self.limits.max_records,
                    }));
                }

                let newline = available.iter().position(|byte| *byte == b'\n');
                let consumed = newline.map_or(available.len(), |offset| offset + 1);
                let record_bytes = newline.map_or(available, |offset| &available[..offset]);
                let decoded_bytes = Self::account_decoded(
                    self.decoded_bytes,
                    consumed,
                    self.limits.max_decoded_bytes,
                )?;
                Self::extend_record(
                    &mut record,
                    record_bytes,
                    ordinal,
                    self.limits.max_record_bytes,
                )?;
                (consumed, decoded_bytes, newline.is_some())
            };
            self.reader.consume(consumed);
            self.decoded_bytes = decoded_bytes;

            if found_newline {
                return self.finish_record(ordinal, record, true).map(Some);
            }
        }
    }

    fn finish_record(
        &mut self,
        ordinal: usize,
        mut record: Vec<u8>,
        newline_terminated: bool,
    ) -> io::Result<RolloutRecord> {
        if record.last() == Some(&b'\r') {
            record.pop();
        }
        let line = String::from_utf8(record)
            .map_err(|_| typed_error(RolloutReadError::InvalidUtf8 { record: ordinal }))?;
        self.records = ordinal;
        Ok(RolloutRecord {
            ordinal,
            line,
            newline_terminated,
        })
    }

    fn account_decoded(current: usize, additional: usize, limit: usize) -> io::Result<usize> {
        let decoded_bytes = current
            .checked_add(additional)
            .ok_or_else(|| typed_error(RolloutReadError::DecodedBytesTooLarge { limit }))?;
        if decoded_bytes > limit {
            return Err(typed_error(RolloutReadError::DecodedBytesTooLarge {
                limit,
            }));
        }
        Ok(decoded_bytes)
    }

    fn extend_record(
        record: &mut Vec<u8>,
        bytes: &[u8],
        ordinal: usize,
        limit: usize,
    ) -> io::Result<()> {
        let record_bytes = record.len().checked_add(bytes.len()).ok_or_else(|| {
            typed_error(RolloutReadError::RecordTooLarge {
                record: ordinal,
                limit,
            })
        })?;
        if record_bytes > limit {
            return Err(typed_error(RolloutReadError::RecordTooLarge {
                record: ordinal,
                limit,
            }));
        }
        reserve_record_buffer(record, bytes.len(), ordinal)?;
        record.extend_from_slice(bytes);
        Ok(())
    }
}

fn reserve_record_buffer(
    record: &mut Vec<u8>,
    additional: usize,
    ordinal: usize,
) -> io::Result<()> {
    record.try_reserve(additional).map_err(|_| {
        typed_error(RolloutReadError::ResourceExhausted {
            resource: RolloutReadResource::RecordBuffer,
            record: ordinal,
        })
    })
}

pub(crate) fn reserve_rollout_items<T>(
    items: &mut Vec<T>,
    additional: usize,
    record: usize,
) -> io::Result<()> {
    items.try_reserve(additional).map_err(|_| {
        typed_error(RolloutReadError::ResourceExhausted {
            resource: RolloutReadResource::ItemList,
            record,
        })
    })
}

pub(crate) fn invalid_json(record: usize, newline_terminated: bool) -> io::Error {
    if newline_terminated {
        typed_error(RolloutReadError::MalformedJson { record })
    } else {
        typed_error(RolloutReadError::TruncatedRecord { record })
    }
}

pub(crate) fn empty_session() -> io::Error {
    typed_error(RolloutReadError::EmptySession)
}

pub(crate) fn worker_failed() -> io::Error {
    typed_error(RolloutReadError::WorkerFailed)
}

fn typed_error(error: RolloutReadError) -> io::Error {
    let kind = match error {
        RolloutReadError::ResourceExhausted { .. } => io::ErrorKind::OutOfMemory,
        RolloutReadError::TruncatedRecord { .. } => io::ErrorKind::UnexpectedEof,
        RolloutReadError::RecordTooLarge { .. }
        | RolloutReadError::DecodedBytesTooLarge { .. }
        | RolloutReadError::TooManyRecords { .. }
        | RolloutReadError::InvalidUtf8 { .. }
        | RolloutReadError::MalformedJson { .. }
        | RolloutReadError::CompressedData { .. } => io::ErrorKind::InvalidData,
        RolloutReadError::EmptySession => io::ErrorKind::Other,
        RolloutReadError::WorkerFailed => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

fn existing_rollout_path(path: &Path) -> Option<PathBuf> {
    let plain_path = plain_rollout_path(path);
    if matches!(plain_path.metadata(), Ok(metadata) if metadata.is_file()) {
        return Some(plain_path);
    }
    let compressed_path = compressed_rollout_path(plain_path.as_path());
    if matches!(compressed_path.metadata(), Ok(metadata) if metadata.is_file()) {
        return Some(compressed_path);
    }
    None
}

fn plain_rollout_path(path: &Path) -> PathBuf {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return path.to_path_buf();
    };
    let Some(plain_name) = file_name.strip_suffix(COMPRESSED_SUFFIX) else {
        return path.to_path_buf();
    };
    path.with_file_name(plain_name)
}

fn compressed_rollout_path(path: &Path) -> PathBuf {
    let plain_path = plain_rollout_path(path);
    let Some(file_name) = plain_path.file_name().and_then(|name| name.to_str()) else {
        return plain_path;
    };
    plain_path.with_file_name(format!("{file_name}{COMPRESSED_SUFFIX}"))
}

fn is_compressed_rollout_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(COMPRESSED_SUFFIX))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;

    fn limits(record: usize, decoded: usize, records: usize) -> RolloutReadLimits {
        RolloutReadLimits {
            max_record_bytes: record,
            max_decoded_bytes: decoded,
            max_records: records,
        }
    }

    fn typed(error: &io::Error) -> RolloutReadError {
        rollout_read_error(error)
            .expect("typed rollout read error")
            .clone()
    }

    #[test]
    fn bounded_reader_accepts_exact_plain_and_compressed_boundaries() -> io::Result<()> {
        let home = TempDir::new()?;
        let plain = home.path().join("rollout.jsonl");
        std::fs::write(&plain, b"1234\n5678\n")?;
        let compressed = home.path().join("rollout-copy.jsonl.zst");
        let output = File::create(&compressed)?;
        let mut encoder = zstd::stream::write::Encoder::new(output, 1)?;
        encoder.write_all(b"1234\n5678\n")?;
        encoder.finish()?;

        for path in [&plain, &compressed] {
            let mut reader = BoundedRolloutReader::open(path, limits(4, 10, 2))?;
            assert_eq!(reader.next_record()?.expect("first").line, "1234");
            assert_eq!(reader.next_record()?.expect("second").line, "5678");
            assert_eq!(reader.next_record()?, None);
        }
        Ok(())
    }

    #[test]
    fn bounded_reader_rejects_record_and_decoded_overflow_before_growth() -> io::Result<()> {
        let home = TempDir::new()?;
        let path = home.path().join("rollout.jsonl");
        std::fs::write(&path, b"12345\n")?;

        let mut record_reader = BoundedRolloutReader::open(&path, limits(4, 64, 8))?;
        let error = record_reader
            .next_record()
            .expect_err("record limit should fail");
        assert_eq!(
            typed(&error),
            RolloutReadError::RecordTooLarge {
                record: 1,
                limit: 4
            }
        );

        let compressed = home.path().join("rollout.jsonl.zst");
        let output = File::create(&compressed)?;
        let mut encoder = zstd::stream::write::Encoder::new(output, 1)?;
        encoder.write_all(b"12345\n")?;
        encoder.finish()?;
        let mut compressed_reader = BoundedRolloutReader::open(&compressed, limits(4, 64, 8))?;
        let error = compressed_reader
            .next_record()
            .expect_err("compressed record limit should fail");
        assert_eq!(
            typed(&error),
            RolloutReadError::RecordTooLarge {
                record: 1,
                limit: 4
            }
        );

        let mut decoded_reader = BoundedRolloutReader::open(&path, limits(8, 5, 8))?;
        let error = decoded_reader
            .next_record()
            .expect_err("decoded limit should fail");
        assert_eq!(
            typed(&error),
            RolloutReadError::DecodedBytesTooLarge { limit: 5 }
        );
        Ok(())
    }

    #[test]
    fn bounded_reader_accepts_valid_unterminated_tail_and_classifies_utf8_and_record_count()
    -> io::Result<()> {
        let home = TempDir::new()?;
        let unterminated = home.path().join("unterminated.jsonl");
        std::fs::write(&unterminated, b"{}\n{\"tail\":true}")?;
        let mut reader = BoundedRolloutReader::open(&unterminated, limits(64, 128, 8))?;
        assert!(
            reader
                .next_record()?
                .expect("first record")
                .newline_terminated
        );
        let tail = reader.next_record()?.expect("valid unterminated tail");
        assert_eq!(tail.line, "{\"tail\":true}");
        assert!(!tail.newline_terminated);
        assert_eq!(reader.next_record()?, None);

        let invalid_utf8 = home.path().join("utf8.jsonl");
        std::fs::write(&invalid_utf8, [0xff, b'\n'])?;
        let mut reader = BoundedRolloutReader::open(&invalid_utf8, limits(64, 128, 8))?;
        let error = reader.next_record().expect_err("UTF-8 should fail");
        assert_eq!(typed(&error), RolloutReadError::InvalidUtf8 { record: 1 });

        let too_many = home.path().join("records.jsonl");
        std::fs::write(&too_many, b"{}\n{}\n")?;
        let mut reader = BoundedRolloutReader::open(&too_many, limits(64, 128, 1))?;
        assert!(reader.next_record()?.is_some());
        let error = reader.next_record().expect_err("record count should fail");
        assert_eq!(typed(&error), RolloutReadError::TooManyRecords { limit: 1 });
        Ok(())
    }

    #[test]
    fn default_record_limit_accepts_valid_records_larger_than_32_mib() -> io::Result<()> {
        let home = TempDir::new()?;
        let path = home.path().join("large.jsonl");
        let payload = "a".repeat(33 * 1024 * 1024);
        let line = serde_json::to_string(&serde_json::json!({ "payload": payload }))
            .map_err(io::Error::other)?;
        std::fs::write(&path, format!("{line}\n"))?;

        assert!(MAX_ROLLOUT_RECORD_BYTES >= 96 * 1024 * 1024);
        let mut reader = BoundedRolloutReader::open(&path, RolloutReadLimits::default())?;
        let record = reader.next_record()?.expect("large record");
        assert!(record.line.len() > 32 * 1024 * 1024);
        assert!(record.newline_terminated);
        let value: serde_json::Value =
            serde_json::from_str(&record.line).map_err(io::Error::other)?;
        assert_eq!(
            value["payload"].as_str().map(str::len),
            Some(33 * 1024 * 1024)
        );
        Ok(())
    }

    #[test]
    fn item_reservation_failure_is_typed_instead_of_panicking() {
        let mut record = Vec::<u8>::new();
        let error = reserve_record_buffer(&mut record, usize::MAX, 6)
            .expect_err("impossible record reservation should fail");
        assert_eq!(
            typed(&error),
            RolloutReadError::ResourceExhausted {
                resource: RolloutReadResource::RecordBuffer,
                record: 6,
            }
        );
        assert!(record.is_empty());

        let mut items = Vec::<u8>::new();
        let error = reserve_rollout_items(&mut items, usize::MAX, 7)
            .expect_err("impossible reservation should fail");
        assert_eq!(
            typed(&error),
            RolloutReadError::ResourceExhausted {
                resource: RolloutReadResource::ItemList,
                record: 7,
            }
        );
        assert!(items.is_empty());
    }

    #[test]
    fn bounded_reader_types_truncated_compressed_data() -> io::Result<()> {
        let home = TempDir::new()?;
        let compressed = home.path().join("rollout.jsonl.zst");
        let output = File::create(&compressed)?;
        let mut encoder = zstd::stream::write::Encoder::new(output, 1)?;
        encoder.write_all("generated-record\n".repeat(4096).as_bytes())?;
        encoder.finish()?;
        let mut bytes = std::fs::read(&compressed)?;
        bytes.truncate(bytes.len() / 2);
        std::fs::write(&compressed, bytes)?;

        let mut reader = BoundedRolloutReader::open(&compressed, limits(64, 128 * 1024, 10_000))?;
        let error = loop {
            match reader.next_record() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("truncated compressed stream should not reach clean EOF"),
                Err(error) => break error,
            }
        };
        assert!(matches!(
            typed(&error),
            RolloutReadError::CompressedData { .. } | RolloutReadError::TruncatedRecord { .. }
        ));
        Ok(())
    }

    #[test]
    fn bounded_reader_types_invalid_compressed_header() -> io::Result<()> {
        let home = TempDir::new()?;
        let compressed = home.path().join("rollout.jsonl.zst");
        std::fs::write(&compressed, b"not a zstd frame")?;
        let mut reader = BoundedRolloutReader::open(&compressed, RolloutReadLimits::default())?;
        let error = reader
            .next_record()
            .expect_err("invalid compressed header should fail");
        assert_eq!(
            typed(&error),
            RolloutReadError::CompressedData { record: 1 }
        );
        Ok(())
    }
}
