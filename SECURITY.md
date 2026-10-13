# Security policy

Sediment opens evidence from machines that may be compromised, so we treat any problem
reading a file as a security issue.

## Reporting a vulnerability

Please **don't open a public issue**. Report it privately through GitHub instead:
**Security → Report a vulnerability** on this repository.

Include your Sediment version, your operating system, what you did and, if you can, a file
that reproduces the problem. Please remove any real customer data first.

We aim to reply within a few days and to fix confirmed issues in the next release.

## How Sediment protects you

- **Evidence is only read.** Sediment never changes or runs anything from the files and
  images you open.
- **Damaged or malicious files are contained.** A file that can't be read shows an error;
  the rest of your evidence still loads.
- **Extracted files are locked.** They are saved inside a ZIP with the password `infected`,
  so they can't be opened by accident.
- **Nothing leaves your machine unless you send it.** The only automatic network request is
  a daily update check, which you can turn off. VirusTotal and Triage are only contacted
  when you click, and uploads always ask first.
- **Your API keys stay private.** They are only saved if you ask, in a settings file only
  your account can read.
- **Updates are verified.** Releases are built from the public source and published with
  checksums; the installer and in-app updates check them before installing.
- **Spreadsheet-safe exports.** CSV exports can't trigger formulas when opened in Excel.
