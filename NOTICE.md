# Notices

Sediment is licensed under the [PolyForm Small Business License 1.0.0](LICENSE.md).

## Third-party libraries

Sediment is built on open-source Rust crates, including
[egui/eframe](https://github.com/emilk/egui),
[egui_extras](https://github.com/emilk/egui),
[rfd](https://github.com/PolyMeilex/rfd) and
[chrono](https://github.com/chronotope/chrono), each under the MIT and/or Apache-2.0
license. The full dependency list is in `Cargo.lock`.

The Xpress Huffman decompressor in `src/xpress.rs` is an independent implementation of
the algorithm published by Microsoft in [MS-XCA] §2.2.

[MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/
