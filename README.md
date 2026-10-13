# Sediment

*Every action leaves a layer.*

A desktop explorer for Windows forensic artifacts, with the links between them:

| Artifact | What you get |
|---|---|
| **`$MFT`** | Folder tree rebuilt from parent references, deleted entries, hard links, every attribute decoded (`$SI` / `$FN` timestamps, data runs, ADS, raw hex), timestomping flag, resident file content (and ADS) extracted to a ZIP with the password `infected` |
| **`$UsnJrnl:$J`** + **`$Max`** | Change journal as a table and as a folder tree with activity / deletion counts, full paths resolved through the `$MFT` (or the journal itself for folders that no longer exist) |
| **Prefetch (`.pf`)** | Run count and times, loaded files, directories, volumes, trace chains, known attacker tools, capability hints, notable files |

Cross-artifact links:

- **MFT ↔ Journal**: every MFT record has a Journal tab; every journal entry links back to its MFT record.
- **Prefetch → MFT / Journal**: each loaded file shows whether it still exists in the `$MFT` (by MFT reference, or by path on Windows 10+, where prefetch no longer stores per-file references), with one-click jumps to the record and its journal history. The `.pf` file's own creation in the journal gives a first-run estimate.
- **MFT → Prefetch**: an MFT record shows which prefetch files loaded it.
- **Back / Forward** across all views (Alt+← / Alt+→, mouse side buttons).

Files are recognised by content, so names don't matter. Drop files or whole folders
(e.g. a KAPE triage folder or `C:\Windows\Prefetch`) onto the window, or pass them
on the command line:

```
sediment $MFT $J $Max C:\cases\host1\Prefetch
```

## Install

One command, no administrator rights. Details and screenshots: <https://nyanites.github.io/sediment/>

**Windows** (PowerShell):

```powershell
irm https://nyanites.github.io/sediment/install.ps1 | iex
```

**macOS and Linux** (terminal):

```sh
curl -fsSL https://nyanites.github.io/sediment/install.sh | sh
```

The installers ([install.ps1](docs/install.ps1), [install.sh](docs/install.sh)) download the
latest [release](https://github.com/Nyanites/sediment/releases), verify it against the
published SHA-256 checksums, and install for the current user only: Windows to
`%LOCALAPPDATA%\Programs\Sediment` (Start menu shortcut, added to PATH), macOS to
`/Applications/Sediment.app`, Linux to `~/.local/bin/sediment` (app-menu entry). Release
binaries carry [build provenance attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations):
`gh attestation verify <file> -R Nyanites/sediment`.

## Platforms

Windows, macOS and Linux. Everything is plain Rust + [egui](https://github.com/emilk/egui);
Windows 10+ prefetch decompression (Xpress Huffman, [MS-XCA] §2.2) is implemented in
`src/xpress.rs` rather than through `ntdll`, so it works everywhere.

## Building

```
cargo build --release      # target/release/sediment(.exe)
cargo test --release       # parser tests use the files in samples/ when present
```

`cargo test -- --ignored live_prefetch_dir` additionally decodes every file in
`C:\Windows\Prefetch` with both our decoder and Windows' own (run as administrator).

`samples/` holds evidence files for the tests and is not committed. The tests that
need them skip themselves when it is absent. `tests/fixtures/` is committed and always
runs: data compressed by Windows' own Xpress Huffman encoder, plus a small synthetic
Windows 10 prefetch file, so every platform is checked against real Windows output.
Regenerate them on Windows with `cargo test -- --ignored write_`.

CI (`.github/workflows/ci.yml`) tests on Windows, macOS and Linux on every push.

To release, bump `version` in `Cargo.toml` and push a matching tag (`git tag v0.1.1 &&
git push origin v0.1.1`). `.github/workflows/release.yml` then builds Windows (x64, ARM64),
a universal macOS app and Linux (x64, ARM64), and publishes them with `SHA256SUMS.txt`.

## Layout

```
src/mft.rs            $MFT records, attributes, paths, hard links
src/extract.rs        resident $DATA extraction to a password-protected ZIP
src/usn.rs            USN journal records and $Max
src/prefetch.rs       Prefetch (SCCA) parser
src/xpress.rs         Xpress Huffman decompressor
src/app.rs            window, MFT view, loading, shared UI
src/app/journal*.rs   journal view and its folder tree
src/app/pf.rs         prefetch view and cross-artifact links
src/app/nav.rs        back / forward history
src/app/search.rs     wildcard search
```

## Security

Sediment opens files from possibly compromised machines; see [SECURITY.md](SECURITY.md)
for how to report a parsing bug privately and what hardening is in place.

## License

[PolyForm Small Business License 1.0.0](LICENSE.md): free for organizations with fewer
than 100 people and under US$1M revenue. Third-party notices: [NOTICE.md](NOTICE.md).

[MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/
