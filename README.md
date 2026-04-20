# crypto-zig

Zig implementations of common **non-cryptographic** checksums and hashes: **CRC-32** (IEEE / Castagnoli), **CRC-64** (ISO / ECMA), **Adler-32**, and **FNV-1 / FNV-1a** (32 / 64 / 128 bit). APIs are documented in source (see [`src/hash/root.zig`](src/hash/root.zig)) and aligned with Go’s `hash/*` packages where noted for interoperability and test vectors.

**These algorithms are not for authentication, passwords, or attacker-chosen inputs.** Use a cryptographic hash or MAC when a malicious party can influence the data being hashed.

## License

This project is licensed under the [MIT License](LICENSE).

SPDX-License-Identifier: MIT

## Requirements

- Zig **0.17.0-dev.27** or newer (see `minimum_zig_version` in [`build.zig.zon`](build.zig.zon)).

## Add as a dependency

With the Zig package manager, add this package to your `build.zig.zon` dependencies (URL/path and hash as appropriate), then in `build.zig`:

```zig
const crypto_zig_dep = b.dependency("crypto_zig", .{});
const crypto_zig_mod = crypto_zig_dep.module("crypto_zig");
// Pass crypto_zig_mod to your module's .imports
```

Import in application or library code:

```zig
const crypto_zig = @import("crypto_zig");
```

The library root ([`src/root.zig`](src/root.zig)) re-exports hash APIs at the top level for convenience:

| Symbol   | Description |
|----------|-------------|
| `hash`   | Full hash submodule (also access `hash.Hash`, `hash.Hash32`, …) |
| `Adler32`| Adler-32 struct |
| `crc32`  | CRC-32 module (IEEE, Castagnoli, tables) |
| `crc64`  | CRC-64 module (ISO, ECMA, `Digest`) |
| `fnv`    | FNV-1 / FNV-1a types and constants |

## Examples

### CRC-32 (IEEE, one-shot)

```zig
const std = @import("std");
const crypto_zig = @import("crypto_zig");
const crc32 = crypto_zig.crc32;

test "crc32 ieee" {
    const sum = crc32.checksumIEEE("123456789");
    try std.testing.expectEqual(@as(u32, 0xcbf43926), sum);
}
```

### CRC-64 (ISO, incremental `Digest`)

```zig
const std = @import("std");
const crypto_zig = @import("crypto_zig");
const crc64 = crypto_zig.crc64;

test "crc64 digest" {
    var d = crc64.Digest.init(crc64.isoTable());
    d.write("hello");
    try std.testing.expect(d.sum64() != 0);
}
```

### Adler-32

```zig
const std = @import("std");
const crypto_zig = @import("crypto_zig");
const Adler32 = crypto_zig.Adler32;

test "adler32" {
    const sum = Adler32.checksum("example");
    _ = sum;
}
```

### FNV-1a 64-bit

```zig
const std = @import("std");
const crypto_zig = @import("crypto_zig");
const fnv = crypto_zig.fnv;

test "fnv64a" {
    var h = fnv.Fnv64a.new();
    h.write("abc");
    const d = h.sum64();
    _ = d;
}
```

### Streaming writer + flush

Hashers that use `std.Io.Writer.Hashing` must **flush** the writer before reading the digest:

```zig
const crypto_zig = @import("crypto_zig");
const fnv = crypto_zig.fnv;

test "fnv writer" {
    var h = fnv.Fnv64.new();
    const w = h.writer();
    try w.writeAll("hi");
    try w.flush();
    _ = h.sum64();
}
```

### Type-erased `Hash64` facade (CRC-64)

```zig
const crypto_zig = @import("crypto_zig");
const crc64 = crypto_zig.crc64;

test "hash64 facade" {
    var digest = crc64.Digest.init(crc64.isoTable());
    digest.write(&.{ 1, 2, 3 });
    const iface = digest.hash64();
    const x = iface.sum64();
    _ = x;
}
```

More patterns and golden vectors live next to the implementations under [`src/hash/`](src/hash/).

## Build and test

```sh
zig build test
```

## Repository status

The following snapshot was taken from the maintainer’s clone when this README was last updated; your tree may differ.

| Item | Value |
|------|--------|
| Default branch | `main` (tracks `origin/main` when remote exists) |
| Latest recorded commit | `8fa493c` |
| Unversioned files (example) | `go.mod`, `main.go` (local experiments; not part of the Zig package layout) |

Run `git status` and `git log -1 --oneline` for the authoritative current state.

## Project layout

| Path | Role |
|------|------|
| [`build.zig`](build.zig) | Defines `crypto_zig` module and tests |
| [`build.zig.zon`](build.zig.zon) | Package name `crypto_zig`, version `0.0.0` |
| [`src/root.zig`](src/root.zig) | Library root: re-exports hash APIs |
| [`src/hash/root.zig`](src/hash/root.zig) | Hash module overview (`//!` docs) |
| [`src/hash/hash.zig`](src/hash/hash.zig) | `Hash`, `Hash32`, `Hash64`, `Cloner` vtables |
| [`src/hash/adler32.zig`](src/hash/adler32.zig) | Adler-32 |
| [`src/hash/crc32/`](src/hash/crc32/) | CRC-32 (generic + optional aarch64 fast path) |
| [`src/hash/crc64.zig`](src/hash/crc64.zig) | CRC-64 |
| [`src/hash/fnv.zig`](src/hash/fnv.zig) | FNV-1 / FNV-1a |
| [`src/main.zig`](src/main.zig) | Sample executable (imports `crypto_zig` for demos/tests) |

## Contributing

Issues and pull requests are welcome. Please run `zig build test` before submitting changes.
