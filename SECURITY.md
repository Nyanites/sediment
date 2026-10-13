# Security policy

Sediment opens files that may come from compromised machines, so we treat parsing bugs as
security bugs.

## Reporting a vulnerability

Please **don't open a public issue**. Report it privately through GitHub instead:
**Security → Report a vulnerability** on this repository.

Include the Sediment version, your OS, what you did, and, if possible, a file that
reproduces the problem (a minimal `$MFT`, `$J` or `.pf`). Please strip any real customer
data first.

We aim to acknowledge reports within a few days and to fix confirmed issues in the next
release.

## Hardening in place

- Every parser (`$MFT`, `$UsnJrnl:$J` / `$Max`, Prefetch, Xpress Huffman) is bounds-checked
  and fuzz-tested in CI with random and mutated inputs (`src/fuzz_tests.rs`).
- Sizes and counts read from a file never drive allocations directly: they are capped by
  what the file could actually contain, and decoding work per file is budgeted.
- Paths rebuilt from parent references are length-capped, deep folder chains are walked
  iteratively, and a `\` inside a file name can't fake extra path components.
- A parser failure is contained: the file shows an error instead of crashing the app.
- Nothing from an evidence file is ever executed, and Sediment makes no network requests.
- Extracted file content is only written inside a ZIP encrypted with the password
  `infected`, so it isn't run by accident or quarantined mid-analysis.
- CSV exports neutralise spreadsheet formulas (cells starting with `=`, `+`, `-`, `@`,
  tab or CR).
- Releases are built by GitHub Actions from tagged source with pinned actions and
  `--locked` dependencies, published with SHA-256 checksums that the installers verify,
  and carry build provenance attestations
  (`gh attestation verify <file> -R Nyanites/sediment`).
