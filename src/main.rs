mod file_locker;

use std::io::Write;
use std::path::{PathBuf};


#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .init();
    loop {
        let mut name = String::new();
        print!(">>>");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut name).unwrap();
        let name = name.trim().split_once(" ");
        match name {
            Some(("exit", _)) | Some(("quit", _)) => break,
            Some(("lock", target)) => 
            {
                let target = PathBuf::from(target);
                if target.exists() {
                    file_locker::DirLockManager::new(
                        target,
                        "password".to_string(),
                        file_locker::AesLocker::new(),
                    ).lock().await;
                }
            },
            Some(("unlock", target)) => {
                {
                    let target = PathBuf::from(target);
                    if target.exists() {
                        file_locker::DirLockManager::new(
                            target,
                            "password".to_string(),
                            file_locker::AesLocker::new(),
                        ).unlock().await;
                    }
                }
            },
            _ => println!("Unknown command"),
        }

    }
}