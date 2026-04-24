1. Refrain from using `anyhow::Error`. Wherever possible, use concrete error types with `thiserror`
2. Do not *ever* use mod.rs files. Use the new modules system instead. For example, if you have a module named `foo`, create a file named `foo.rs` and put the module code there, all additional files would then go to `./foo/` Do not create a `foo/mod.rs` file.
