//! Binary for generating FFI bindings (library mode).
//! Example: `uniffi-bindgen generate --library <cdylib> --language swift --out-dir <dir>`.
fn main() {
    uniffi::uniffi_bindgen_main();
}
