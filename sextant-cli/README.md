# sextant-re

This crate publishes the `sextant` command-line tool. The bare name `sextant`
was already taken on crates.io, so the package is named `sextant-re` while the
installed binary keeps the name `sextant`.

```bash
cargo install sextant-re
sextant --help
```

Sextant infers the structure of unknown binary file formats and network
protocols from sample data, then generates parsers that it has verified against
those samples (Kaitai, ImHex, Wireshark, 010), with an honest per-field
confidence report.

See the project README and documentation at
<https://github.com/NotACop38/Sextant> for the full story, the verification
model, and usage examples.

## License

Dual licensed under either of MIT or Apache-2.0 at your option.
