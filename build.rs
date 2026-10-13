fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico")
            .set("ProductName", "Sediment")
            .set("FileDescription", "Sediment - Windows forensic artifact explorer")
            .set("OriginalFilename", "sediment.exe");
        res.compile().expect("failed to compile Windows resources");
    }
}
