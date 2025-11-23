mod file_locker;

use std::io::Write;
use std::path::{PathBuf};

use std::time::{Duration, Instant};

/// 一个基于 RAII 的计时器。
#[derive(Debug)]
struct Timer {
    start_time: Instant,
    name: &'static str,
}

impl Timer {
    /// 创建一个新的计时器并立即开始计时。
    pub fn new(name: &'static str) -> Self {
        println!("[Timer: '{}'] 开始计时...", name);
        Timer {
            start_time: Instant::now(),
            name,
        }
    }

    pub fn print(&self){
        // `Instant::elapsed()` 方法返回从 `start_time` 到现在的时间差
        let duration = self.elapsed();
        
        // 格式化输出，使其更具可读性
        println!(
            "[Timer: '{}'] 计时结束。总耗时: {:?}",
            self.name, duration
        );
    }

    fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}


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
                let _time = Timer::new("加密");
                let l = file_locker::DirLockManager::new(
                    vec![target.to_string()],
                    "password".to_string(),
                    file_locker::AesLocker::new(),
                );
                l.lock().await;
                println!("{}/{}  err:{}", l.get_done_count(), l.get_total_count(), l.get_err_count());
                _time.print();
            },
            Some(("unlock", target)) => 
            {    
                let _time = Timer::new("解密");
                file_locker::DirLockManager::new(
                    vec![target.to_string()],
                    "password".to_string(),
                    file_locker::AesLocker::new(),
                ).unlock().await;
                
                _time.print();
                
            },
            _ => println!("Unknown command"),
        }

    }
}