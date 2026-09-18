# ferrisetw2

This repository is a fork of [n4r1b/ferrisetw](https://github.com/n4r1b/ferrisetw), maintained separately from upstream. All changes since the fork point were implemented by AI coding agents under human direction.

Changes relative to upstream:

- Correctness: ~40 bug fixes across the parser, serializer, schema locator and native layer; undecodable properties now degrade gracefully instead of failing the whole event
- Features: runtime provider enable/disable, session statistics, nested struct decoding and serialization, extended data (SID, stack frames, container id), capture-state (rundown) requests, event/executable/stackwalk filters, kernel session configuration via `TraceSetInformation`, configurable clock type
- Performance: multi-level schema/name caching, memchr scans, narrower lock scopes, O(1) provider dispatch, fewer TDH round-trips
- Testing & tooling: unit suite grown from 44 to 143 tests plus 30 doctests, admin-gated live-session integration tests, TDH ground-truth tests, edition 2024, clippy clean

## Examples

You can find examples within the [crate documentation on docs.rs](https://docs.rs/ferrisetw2), as well as the [examples](./examples) and the [tests](./tests) folders.

## Documentation

This crate is documented at [docs.rs](https://docs.rs/crate/ferrisetw2/latest).

### Acknowledgments

- The team at Microsoft who develop KrabsETW
- [Shaddy](https://github.com/Shaddy), who taught [n4r1b](https://github.com/n4r1b) pretty much all the Rust he knows
- [n4r1b](https://github.com/n4r1b) for creating upstream great crate, [daladim](https://github.com/daladim) for adding even more features
