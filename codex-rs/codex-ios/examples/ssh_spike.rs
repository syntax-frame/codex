//! Host test for the SSH execution engine: connect to Atlas over SSH with the
//! dedicated app key and run real commands (including a passwordless `sudo`).
//! Run: `cargo run -p codex-ios --example ssh_spike`

use codex_ios::ssh::ssh_exec;

#[tokio::main]
async fn main() {
    let home = std::env::var("HOME").expect("HOME");
    let key_path = format!("{home}/.ssh/agentapp_key");
    let host = "127.0.0.1";
    let port = 22u16;
    let user = "ivica";

    let command = "echo '--- whoami ---'; whoami; \
                   echo '--- host ---'; uname -n; \
                   echo '--- pwd ---'; pwd; \
                   echo '--- sudo (passwordless) ---'; sudo -n whoami; \
                   echo '--- exit ---'";

    println!("connecting to {user}@{host}:{port} with key {key_path}");
    match ssh_exec(host, port, user, &key_path, command).await {
        Ok(out) => {
            println!("=== REMOTE OUTPUT (exit {}) ===", out.exit_code);
            println!("{}", out.output);
            println!("=== SSH_EXEC_OK ===");
        }
        Err(e) => {
            eprintln!("=== SSH_EXEC_FAILED: {e} ===");
            std::process::exit(1);
        }
    }
}
