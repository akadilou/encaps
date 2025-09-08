# Encaps (core + CLI)
## Build
cargo build --release -p cryq8 && cargo build --release -p cryq8_cli
## Test
cargo test -p cryq8
## Usage CLI
./target/release/cryq8_cli encpwd --password "Fort!2025" --inp doc.pdf --out doc.pdf.q8msg --mime application/pdf --filename doc.pdf
./target/release/cryq8_cli decpwd --password "Fort!2025" --inp doc.pdf.q8msg --out doc_restored.pdf
