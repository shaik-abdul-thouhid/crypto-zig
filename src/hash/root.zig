//! Non-cryptographic checksums and string-oriented hashes (CRC family, Adler-32, FNV).
//!
//! ## Security
//!
//! These algorithms are **not** suitable for authentication, integrity against malicious
//! actors, or password handling. Use a cryptographic primitive (e.g. HMAC, BLAKE2, SHA-256)
//! when an adversary can choose inputs.
//!
//! ## Import
//!
//! From this package root, use the submodule you need:
//!
//! ```zig
//! const crypto = @import("root"); // or your dependency name
//! const Adler32 = crypto.hash.Adler32;
//! const crc32 = crypto.hash.crc32;
//! const crc64 = crypto.hash.crc64;
//! const fnv = crypto.hash.fnv;
//! ```
//!
//! ## Submodules
//!
//! - **`Adler32`** — Rolling Adler-32 checksum (RFC 1950 / zlib-style); incremental updates and optional binary state.
//! - **`crc32`** — CRC-32 with IEEE (PKZIP) and Castagnoli polynomials; optional aarch64 hardware acceleration; custom tables via `generic`.
//! - **`crc64`** — CRC-64 with ISO/ECMA polynomials, `Digest` for streaming, slicing-by-8 for long inputs.
//! - **`fnv`** — FNV-1 and FNV-1a for 32/64/128-bit digests; behavior aligned with Go `hash/fnv` (constants, digest layout, marshal magics).
//! - **`Hash`**, **`Hash32`**, **`Hash64`**, **`Cloner`** — Type-erased interfaces (`hash.zig`) for code that works with any concrete hasher implementation.
//!
//! ## Usage patterns
//!
//! - **One-shot**: `crc32.checksumIEEE(data)`, `crc64.checksum(data, crc64.isoTable())`, `fnv.Fnv64.new()` then `write` + `sum` / `sum64`.
//! - **Incremental**: Hold a `crc64.Digest`, `fnv.Fnv64`, or `Adler32`; call `write` (or `write` via `writer()`), then read the digest. If you use
//!   [`std.Io.Writer`](https://ziglang.org/documentation/master/std/#std.Io.Writer) with a hashing writer, **`flush()`** the writer before reading the digest.
//! - **Erased `Hash`**: Concrete types expose `.hash()`, `.hash32()`, or `.hash64()` returning a `Hash` / `Hash32` / `Hash64` facade for generic code.
//!
//! ## Allocators and `sum`
//!
//! Functions that return `[]u8` allocate with the allocator you pass; **free** the slice when done. Calling `sum` does not mutate hasher state.
//!
//! ## Endianness
//!
//! Digest bytes from `sum` are big-endian where a byte order is defined (e.g. FNV, CRC64 `Digest.sum`). Integer accessors (`sum32`, `sum64`) return native
//! values matching those bytes.
//!
//! ## Reference behavior
//!
//! Where noted in source files, APIs and test vectors follow Go’s `hash/adler32`, `hash/crc32`, `hash/crc64`, and `hash/fnv`. That is a portability aid, not a
//! guarantee that future Go versions will stay identical for undocumented details.
//!
//! ## Examples
//!
//! Unit tests next to each implementation are executable examples (e.g. golden vectors, writer + flush).
const hash = @import("hash.zig");

pub const Adler32 = @import("adler32.zig").Adler32;
pub const crc32 = @import("crc32/root.zig");
pub const crc64 = @import("crc64.zig");
pub const fnv = @import("fnv.zig");

pub const Hash = hash.Hash;
pub const Hash32 = hash.Hash32;
pub const Hash64 = hash.Hash64;
pub const Cloner = hash.Cloner;
