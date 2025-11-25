mod file_locker;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use eframe::egui;
use egui::{ComboBox};
use rfd::{AsyncFileDialog};
use tracing::{info, error};
use tracing_subscriber::{fmt, EnvFilter};

const SIMPLE_LOCK_DEFAULT_PASSWORD: &str = "laull";

/// 计时器
#[derive(Debug, Clone)]
struct Timer {
    start_time: Instant,
}

impl Timer {
    fn new() -> Self {
        Timer {
            start_time: Instant::now(),
        }
    }

    fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    fn formatted_duration(&self) -> String {
        let duration = self.elapsed();
        format!("{:.3?}", duration)
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
    locker_method: file_locker::LockMethod,
    locker_manager: Option<Arc<file_locker::DirLockManager>>,
    selected_files: Arc<Mutex< Vec<String >>>,
    password: String,
    operation: Operation,
    total_count: u64,
    done_count: u64,
    err_count: u64,
    timer: Option<Timer>,
    result_message: String,
    is_working: bool,
    ui_dark_mode: bool,
    ui_password_hide: bool,
    ui_process_rename_file: bool,
    ui_process_rename_dir: bool,
    err_messages: Arc<Mutex<Vec<String>>>,
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

        _ctx.set_visuals(egui::Visuals::light());

        Self {
            locker_method: file_locker::LockMethod::Simple,
            locker_manager: None,
            selected_files: Arc::new(Mutex::new(Vec::new())),
            password: "".to_string(),
            operation: Operation::None,
            total_count: 0,
            done_count: 0,
            err_count: 0,
            timer: None,
            result_message: String::new(),
            is_working: false,
            ui_password_hide: true,
            ui_dark_mode: false,
            ui_process_rename_file: true,
            ui_process_rename_dir: true,
            err_messages: Arc::new(Mutex::new(vec![])),
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

    fn init_lock_or_unlock(&mut self) -> Result<(), String>{
        if self.selected_files
            .lock()
            .map_err(|e| 
                format!("无法获取选中文件列表的锁: {}", e))?
            .is_empty() {
            self.result_message = "请先选择文件或文件夹".to_string();
            return Err("空输入".to_string());
        }

        let paths = self.selected_files.lock().unwrap().clone();
        let password = 
            if self.locker_method == file_locker::LockMethod::Simple{
                SIMPLE_LOCK_DEFAULT_PASSWORD.to_string()
            }else{
                self.password.clone()
            };
            
        if password.is_empty() {
            self.result_message = "密码不为空, 请输入密码".to_string();
            return Err("空密码".to_string());
        }

        let manager = Arc::new(
            self.locker_method.new_locker_manager(
                paths,
                password,
        ));

        self.locker_manager = Some(manager);
        self.is_working = true;
        self.total_count = 0;
        self.done_count = 0;
        self.err_count = 0;
        Ok(())
    }

    fn lock_files(&mut self) {
        if let Err(e) = self.init_lock_or_unlock(){
            error!("lock files error: {}", e);
            return;
        }
        self.operation = Operation::Locking;
        self.timer = Some(Timer::new());
        let manager = self.locker_manager.clone();
        let process_rename_file = self.ui_process_rename_file;
        let process_rename_dir =  self.ui_process_rename_dir;
        let err_messages = self.err_messages.clone();
        // 后台执行
        if let Some(manager) = manager{
            tokio::spawn(async move {
                *err_messages.lock().unwrap() = manager.lock(
                    process_rename_file, 
                    process_rename_dir
                ).await;
                info!("加密完成");
            });
        }
    }

    fn unlock_files(&mut self) {
        if let Err(e) = self.init_lock_or_unlock(){
            error!("unlock files error: {}", e);
            return;
        }
        self.operation = Operation::Unlocking;
        self.timer = Some(Timer::new());
        let manager = self.locker_manager.clone();
        let err_messages = self.err_messages.clone();
        // 后台执行
        if let Some(manager) = manager{
            tokio::spawn(async move {
               *err_messages.lock().unwrap() = 
                    manager.unlock().await;
                info!("解密完成");
            });
        }
    }

    fn update_progress(&mut self) {
        // 进度更新
        if self.locker_manager.is_some() {
            self.total_count = self.locker_manager.as_ref().unwrap().get_total_count();
            self.done_count = self.locker_manager.as_ref().unwrap().get_done_count();
            self.err_count = self.locker_manager.as_ref().unwrap().get_err_count();
            
            if self.total_count <= self.done_count + self.err_count && 
                self.locker_manager.as_ref().unwrap().is_done() 
            {
                self.operation_complete();
            }
        }
    }

    fn operation_complete(&mut self) {
        self.is_working = false;
        if let Some(timer) = &self.timer {
            self.result_message = format!(
                "操作完成！成功{}个 失败{}个 \n耗时: {}\n{}",
                self.done_count,
                self.err_count,
                timer.formatted_duration(),
                self.err_messages.lock().unwrap().join("\n")
            );
        }
        self.operation = Operation::None;
        self.total_count = 0;
        self.done_count = 0;
        self.err_count = 0;
        // 停止计时器
        self.timer = None;
    }
}

impl eframe::App for FileLockerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.update_progress();

        egui::Area::new( "floating_toggle".into())
            .fixed_pos(egui::pos2(ctx.available_rect().max.x - 30.0, 10.0)) 
            .show(ctx, |ui| {
                if ui.button("🌙").clicked() {
                    self.ui_dark_mode = !self.ui_dark_mode;
                }
                // 自动更新主题
                if self.ui_dark_mode {
                    ctx.set_visuals(egui::Visuals::dark());
                } else {
                    ctx.set_visuals(egui::Visuals::light());
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui|{
                ui.heading("Laull的文件加密 / 解密器");
                ui.hyperlink_to("My Website", "https://laull.top");
            });

            ui.add_space(10.0);

            // ================================
            // 文件选择 + 路径显示（左右结构）
            // ================================
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("选择文件或文件夹");
                        if ui.button("选择文件").clicked() {
                            self.select_files();
                        }
                        if ui.button("选择文件夹").clicked() {
                            self.select_folder();
                        }
                    });

                    let files = self.selected_files.lock().unwrap();
                    ui.separator();
                    
                    ui.label(format!("已选择： 共{}个", files.len()));
                    let text = files.join("\n");
                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])     // 不要自动收缩
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(text)
                            );
                        });
                    
                });
            });

            ui.add_space(10.0);

            // ================================
            // 密码输入区域
            // ================================
            ui.horizontal(|ui| {
                ui.label("密码:");
                // 简单加密无密码
                if self.locker_method == file_locker::LockMethod::Simple{
                    ui.add_enabled(false,
                    egui::TextEdit::singleline(&mut "快速加密无密码，带密码加密需用其他模式")
                );
                }else{
                    ui.add_enabled(true,
                        egui::TextEdit::singleline(&mut self.password)
                        .password(self.ui_password_hide)
                    );
                }
                
                let button_hide_text = if self.ui_password_hide {
                    "显示"
                }else{
                    "隐藏"
                };
                if ui.button(button_hide_text).clicked() {
                    self.ui_password_hide = !self.ui_password_hide;
                }
            });
            
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.ui_process_rename_file, "混淆文件名");
                ui.checkbox(&mut self.ui_process_rename_dir, "混淆文件夹名");
            });
            ui.add_space(10.0);

            // ================================
            // 操作 + 进度（左右布局）
            // ================================
            // 按钮区域
            ui.horizontal(|ui| {
                ui.label("加密模式：");

                ComboBox::from_label("")
                    .width(200.0)
                    .selected_text(self.locker_method.display_name()) // 使用枚举的显示名称
                    .show_ui(ui, |ui| {
                        // 为每个枚举变体添加一个选项
                        ui.selectable_value(&mut self.locker_method, 
                            file_locker::LockMethod::Simple, 
                            file_locker::LockMethod::Simple.display_name());
                        ui.selectable_value(&mut self.locker_method, 
                            file_locker::LockMethod::Aes, 
                            file_locker::LockMethod::Aes.display_name());
                        ui.selectable_value(&mut self.locker_method, 
                            file_locker::LockMethod::Chacha20, 
                            file_locker::LockMethod::Chacha20.display_name());
                    });
                
                if ui.add_enabled(!self.is_working,
                    egui::Button::new("加密").min_size(egui::vec2(80.0, 23.0))
                ).clicked() {
                    self.lock_files();
                }

                if ui.add_enabled(!self.is_working,
                    egui::Button::new("解密").min_size(egui::vec2(80.0, 23.0))
                ).clicked() {
                    self.unlock_files();
                }
            });

            // 结果区域
            ui.with_layout(
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    if !self.result_message.is_empty() {
                        ui.group(|ui| {
                            egui::ScrollArea::vertical()
                                .id_salt("result_scroll")
                                .auto_shrink([false; 2])      // 不自动收缩，保持固定区域
                                .max_height(70.0)            // 设置固定高度
                                .show(ui, |ui| {
                                    ui.label(&self.result_message);
                                });
                        });
                    }
                }
            );


            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);
            // 右侧进度显示
            ui.horizontal(|ui| {

                ui.label(match self.operation {
                    Operation::Locking => "加密中...",
                    Operation::Unlocking => "解密中...",
                    _ => "未开始任务...",
                });
                if self.is_working {
                    ui.add(
                        egui::ProgressBar::new
                        (self.done_count as f32 / self.total_count as f32)
                            .desired_width(200.0)
                            .show_percentage(),
                    );

                    if let Some(t) = &self.timer {
                        ui.label(format!("已运行: {}", t.formatted_duration()));
                    }
                }
            });

        });

        ctx.request_repaint();
    }
}

#[tokio::main]
async fn main() -> Result<(), eframe::Error> {

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("error"))
        .with_timer(fmt::time::UtcTime::rfc_3339()) // 使用 UTC 时间和 RFC3339 格式
        .init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 500.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };

    eframe::run_native(
        "文件加密解密工具@laull",
        options,
        Box::new(|_cc| 
            Ok(Box::new(FileLockerApp::new(&_cc.egui_ctx)))),
    )
}