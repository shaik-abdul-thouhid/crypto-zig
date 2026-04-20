//! Package root. See [`hash/root.zig`](hash/root.zig) for `hash` submodule documentation (API overview, security, I/O).
const std = @import("std");

pub const hash = @import("./hash/root.zig");

pub const Adler32 = hash.Adler32;
pub const crc32 = hash.crc32;
pub const crc64 = hash.crc64;
pub const fnv = hash.fnv;

test {
    _ = hash.Adler32;
    _ = hash.crc32;
    _ = hash.crc64;
    _ = hash.fnv;
}
