# Build a DSM package

Install Python 3.11+, Zig, cargo-zigbuild, and the Rust aarch64-unknown-linux-musl target. From the repository root, run:

    cargo fetch --locked
    sh packaging/rebuild.sh
    python3 packaging/verify.py packaging/dist/pocketmail-rtd1296-0.1.6-1.spk

The recipe builds an engineering sample for rtd1296. The verifier checks archive structure, CPU type and lifecycle hooks locally. Test installation, upgrade, backup and recovery on a disposable DSM instance before using a package with live mail.
