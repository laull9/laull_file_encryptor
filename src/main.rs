mod file_locker;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use eframe::egui;
use rfd::AsyncFileDialog;
use tracing::{info, warn, debug, error};
use tracing_subscriber::{fmt, EnvFilter};


/// 一个基于 RAII 的计时器
#[derive(Debug, Clone)]
struct Timer {
    start_time: Instant,
    name: &'static str,
}

impl Timer {
    fn new(name: &'static str) -> Self {
        Timer {
            start_time: Instant::now(),
            name,
        }
    }

    fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    fn formatted_duration(&self) -> String {
        let duration = self.elapsed();
        format!("{:?}", duration)
    }
}

#[derive(PartialEq, Clone)]
enum Operation {
    None,
    Locking,
    Unlocking,
}

#[derive(Clone)]
struct FileLockerApp {
    locker_manager: Option<Arc<file_locker::DirLockManager>>,
    selected_files: Arc<Mutex< Vec<String >>>,
    password: String,
    operation: Operation,
    progress: f32,
    timer: Option<Timer>,
    result_message: String,
    is_working: bool,
}

impl FileLockerApp {
    fn new(_ctx: &egui::Context) -> Self {

        let custom_font_data = include_bytes!("../font/LXGWWenKaiLite-Regular.ttf");
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "CustomFont".to_string(),
            egui::FontData::from_owned(custom_font_data.to_vec().into()).into(),
        );

        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "CustomFont".to_string());

        _ctx.set_fonts(fonts);

        _ctx.set_pixels_per_point(2.5);

        Self {
            locker_manager: None,
            selected_files: Arc::new(Mutex::new(Vec::new())),
            password: "password".to_string(),
            operation: Operation::None,
            progress: 0.0,
            timer: None,
            result_message: String::new(),
            is_working: false,
        }
    }

    fn select_files(&mut self) {
        let files = AsyncFileDialog::new()
            .add_filter("All files", &["*"])
            .pick_files();
        
        let s_files = self.selected_files.clone();
        tokio::spawn(async move {
            if let Some(handle) = files.await {
                let mut s_files_lock = s_files.lock().unwrap();
                *s_files_lock = handle.iter()
                .map(|f| 
                    f.path().to_string_lossy().into_owned())
                .collect();
                println!("Selected files");
            }
        });
    }

    fn select_folder(&mut self) {
        let folder = AsyncFileDialog::new().pick_folder();
        
        let s_files = self.selected_files.clone();
        tokio::spawn(async move {
            if let Some(handle) = folder.await {
                let path = handle.path().to_string_lossy();
                let mut s_files_lock = s_files.lock().unwrap();
                *s_files_lock = vec![path.clone().into_owned()];

                println!("Selected folder: {:?}", path);
            }
        });
    }

    fn lock_files(&mut self) {
        if self.selected_files.lock().unwrap().is_empty() {
            self.result_message = "请先选择文件或文件夹".to_string();
            return;
        }

        // 1. 初始化 DirLockManager, 存入 UI 状态
        let paths = self.selected_files.lock().unwrap().clone();
        let password = self.password.clone();

        let manager = Arc::new(file_locker::DirLockManager::new(
            paths,
            password,
            file_locker::AesLocker::new(),
        ));

        self.locker_manager = Some(manager.clone());
        self.is_working = true;
        self.operation = Operation::Locking;
        self.progress = 0.0;
        self.timer = Some(Timer::new("加密"));

        // 2. 后台执行 lock()（只传 Arc，不传 app）
        tokio::spawn(async move {
            manager.lock().await;
            info!("加密完成");
        });
    }

    fn unlock_files(&mut self) {
        if self.selected_files.lock().unwrap().is_empty() {
            self.result_message = "请先选择文件或文件夹".to_string();
            return;
        }

        let paths = self.selected_files.lock().unwrap().clone();
        let password = self.password.clone();

        let manager = Arc::new(file_locker::DirLockManager::new(
            paths,
            password,
            file_locker::AesLocker::new(),
        ));

        self.locker_manager = Some(manager.clone());
        self.is_working = true;
        self.operation = Operation::Unlocking;
        self.progress = 0.0;
        self.timer = Some(Timer::new("解密"));
        tokio::spawn(async move {
            manager.unlock().await;
            info!("解密完成");
        });
    }

    fn update_progress(&mut self) {
        // 进度更新
        if self.locker_manager.is_some() {
            let total_count = self.locker_manager.as_ref().unwrap().get_total_count();
            let done_count = self.locker_manager.as_ref().unwrap().get_done_count();
            let err_count = self.locker_manager.as_ref().unwrap().get_err_count();
            self.progress = done_count as f32 / total_count as f32 ;
            
            if total_count <= done_count + err_count {
                self.operation_complete();
            }
        }
    }

    fn operation_complete(&mut self) {
        self.is_working = false;
        self.progress = 0.0;
        if let Some(timer) = &self.timer {
            self.result_message = format!(
                "操作完成！\n耗时: {}",
                timer.formatted_duration()
            );
        }
        self.operation = Operation::None;
        // 停止计时器
        self.timer = None;
    }
}

impl eframe::App for FileLockerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 更新进度（模拟）
        self.update_progress();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("文件加密/解密工具");
            
            // 文件选择区域
            ui.group(|ui| {
                ui.label("选择文件或文件夹:");
                ui.horizontal(|ui| {
                    if ui.button("选择文件").clicked() {
                        self.select_files();
                    }
                    if ui.button("选择文件夹").clicked() {
                        self.select_folder();
                    }
                });
                
                // 显示已选择的文件
                if !self.selected_files.lock().unwrap().is_empty() {
                    ui.label("已选择:");
                    for file in self.selected_files.lock().unwrap().clone() {
                        ui.label(file);
                    }
                }
            });

            ui.separator();

            // 路径输入区域
            ui.group(|ui| {
                ui.label("路径:");
                let paths: Vec<String> = self.selected_files
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|p| p.to_string())
                    .collect();
                ui.text_edit_singleline(&mut paths.join(" "));
            });

            // 密码输入区域
            ui.group(|ui| {
                ui.label("密码:");
                ui.text_edit_singleline(&mut self.password);
            });

            ui.separator();

            // 操作按钮区域
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    if ui.add_enabled(!self.is_working, egui::Button::new("🔒 加密")).clicked() {
                        self.lock_files();
                    }
                    
                    if ui.add_enabled(!self.is_working, egui::Button::new("🔓 解密")).clicked() {
                        self.unlock_files();
                    }
                });

                // 进度显示区域
                ui.vertical(|ui| {
                    if self.is_working {
                        let operation_text = match self.operation {
                            Operation::Locking => "加密中...",
                            Operation::Unlocking => "解密中...",
                            Operation::None => "",
                        };
                        
                        ui.label(operation_text);
                        ui.add(egui::ProgressBar::new(self.progress).show_percentage());
                        
                        if let Some(timer) = &self.timer {
                            ui.label(format!("已运行: {}", timer.formatted_duration()));
                        }
                    }
                });
            });

            ui.separator();

            // 结果显示区域
            if !self.result_message.is_empty() {
                ui.group(|ui| {
                    ui.label("操作结果:");
                    ui.label(&self.result_message);
                });
            }

            // 状态栏
            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("状态:");
                    if self.is_working {
                        ui.label("工作中");
                    } else {
                        ui.label("就绪");
                    }
                });
            });
        });

        // 请求重绘以更新进度
        ctx.request_repaint();
    }
}

#[tokio::main]
async fn main() -> Result<(), eframe::Error> {

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("debug"))
        .with_timer(fmt::time::UtcTime::rfc_3339()) // 使用 UTC 时间和 RFC3339 格式
        .init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 400.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };

    eframe::run_native(
        "文件加密解密工具",
        options,
        Box::new(|_cc| 
            Ok(Box::new(FileLockerApp::new(&_cc.egui_ctx)))),
    )
}