# Contributing to Pocketmail

Build with stable Rust supporting edition 2024, Cargo and a C compiler for bundled SQLite and ring. Run `cargo test --locked` from the project root and `node --test worker/test/index.test.js` with a current Node.js installation. The [MX integration lab](tests/mx-lab/README.md) exercises Postfix delivery in Docker.

Open an issue describing the expected and observed behavior, version, and a minimal synthetic example. Use fictional addresses and generated messages. Keep credentials, private keys, live mail, and operator logs out of issues and patches.

For a pull request, describe the change, the checks you ran, and any effect on existing mail stores or configuration. Add a regression test for a bug fix. Contributions are distributed under the project's [MIT license](LICENSE). Preserve upstream copyright and license notices when adding dependencies.
