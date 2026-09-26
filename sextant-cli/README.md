# sextant-re

This crate provides the `sextant` command-line tool. The crate name `sextant`
belongs to an unrelated project on crates.io, so this package is named
`sextant-re`; the installed binary is still `sextant`.

```bash
cargo install sextant-re                 # statistics-only, no network code
cargo install sextant-re --features llm  # adds the opt-in model pass
sextant --help
```

Sextant infers the structure of unknown binary file formats and network
protocols from sample files. Every structural hypothesis is executed natively
against the samples and scored, and the chosen one is reported with a
per-field confidence and exported as a Kaitai Struct, Wireshark Lua, ImHex, or
010 Editor parser specification. A language model can propose names, roles,
and refinements when you opt in with `--provider`, but a proposal is kept only
when the native executor confirms it does not lower the fit.

Native fit on your samples is evidence, not proof: it does not establish what
fields mean, how the format behaves on samples you did not supply, or how a
generated parser behaves in its own runtime. The documentation says exactly
what is verified and how.

See <https://github.com/NotACop38/Sextant> for the documentation, the
benchmark, and the security notes. Analyze potentially malicious samples in an
isolated environment.

## License

Dual licensed under either of MIT or Apache-2.0 at your option.
