# LimniFS Python reference reader

Independent Python reference reader for the
[LimniFS](https://github.com/limnifs/limnifs) format.

This reader is written **from the spec only** — it never reads the Rust
implementation. It is the spec-sufficiency oracle: if the Rust reader and this
reader agree on the conformance vectors, the spec is unambiguous; if they
disagree, the spec has a gap.

Part of the [LimniFS](https://github.com/limnifs) project.
