// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // AppImage only: default GTK to X11, but let an exported GDK_BACKEND win.
    // This used to live in the AppRun hook of our patched linuxdeploy GTK plugin;
    // tauri-bundler 2.12 embeds its own copy of that plugin, which no longer sets
    // GDK_BACKEND at all. The AppImage runtime exports APPIMAGE, so .deb/.rpm
    // installs keep GTK's own backend choice. Set before anything initialises
    // GTK and before any thread exists, which is what makes set_var sound here.
    #[cfg(target_os = "linux")]
    if std::env::var_os("APPIMAGE").is_some() && std::env::var_os("GDK_BACKEND").is_none() {
        std::env::set_var("GDK_BACKEND", "x11");
    }
    unissh_lib::run()
}
