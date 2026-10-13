#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod extract;
#[cfg(test)]
mod fuzz_tests;
mod mft;
mod prefetch;
mod usn;
mod xpress;

fn main() -> eframe::Result {
    let initial = app::file_args();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Sediment - Windows forensic artifact explorer")
            .with_inner_size([1500.0, 900.0])
            .with_min_inner_size([800.0, 480.0])
            .with_drag_and_drop(true)
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png"))
                    .expect("embedded icon is a valid PNG"),
            ),
        ..Default::default()
    };
    eframe::run_native(
        "Sediment",
        options,
        Box::new(move |cc| Ok(Box::new(app::MftApp::new(cc, initial)))),
    )
}
