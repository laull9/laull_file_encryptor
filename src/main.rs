#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod ui;
mod file_encryptor;

use std::sync::{Arc};
use tracing_subscriber::{fmt};

#[tokio::main]
async fn main() -> Result<(), eframe::Error> {

    tracing_subscriber::fmt()
        .with_timer(fmt::time::UtcTime::rfc_3339()) // 使用 UTC 时间和 RFC3339 格式
        .init();

    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([700.0, 540.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };

    // 加载图标
    let icon_data = include_bytes!("../assets/ico/l.png");
    let img = image::load_from_memory_with_format(icon_data, image::ImageFormat::Png).unwrap();
    let rgba_data = img.into_rgba8();
    let (w,h)=(rgba_data.width(),rgba_data.height());
    let raw_data: Vec<u8> = rgba_data.into_raw();
    options.viewport.icon=Some(Arc::<egui::IconData>::new(egui::IconData { rgba:  raw_data, width: w, height: h }));

    eframe::run_native(
        "文件加密解密工具@laull",
        options,
        Box::new(|_cc| 
            Ok(Box::new(ui::FileEncryptorApp::new(&_cc.egui_ctx)))),
    )
}