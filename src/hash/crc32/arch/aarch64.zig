//! AArch64 **CRC32** extension helpers for IEEE and Castagnoli CRC-32.
//!
//! Only compiled when the target has `.aarch64` + `.crc`; otherwise use [`crc32/generic.zig`](../generic.zig).
//! Normal callers should use [`crc32.updateIEEE`](../root.zig) / [`updateCastagnoli`](../root.zig), which
//! dispatch here when available.
//!
//! **Contract:** `archUpdateIEEE` matches the IEEE polynomial; `archUpdateCastagnoli` matches Castagnoli.
//! Passing arbitrary `crc` is allowed (same as Go `Update` chaining).
const std = @import("std");
const builtin = @import("builtin");
const generic = @import("../generic.zig");

inline fn hasCRC32() bool {
    return builtin.cpu.has(.aarch64, .crc);
}

comptime {
    if (!hasCRC32()) {
        @compileError("CRC32 is not supported on this architecture");
    }
}

fn crc32cx_asm(crc: u32, data: u64) u32 {
    var c = crc;
    asm volatile ("crc32cx w0, w0, x1"
        : [c] "+{w0}" (c),
        : [d] "{x1}" (data),
    );
    return c;
}

fn crc32cw_asm(crc: u32, data: u32) u32 {
    var c = crc;
    asm volatile ("crc32cw w0, w0, w1"
        : [c] "+{w0}" (c),
        : [d] "{w1}" (data),
    );
    return c;
}

fn crc32ch_asm(crc: u32, data: u16) u32 {
    var c = crc;
    const w: u32 = data;
    asm volatile ("crc32ch w0, w0, w1"
        : [c] "+{w0}" (c),
        : [d] "{w1}" (w),
    );
    return c;
}

fn crc32cb_asm(crc: u32, data: u8) u32 {
    var c = crc;
    const w: u32 = data;
    asm volatile ("crc32cb w0, w0, w1"
        : [c] "+{w0}" (c),
        : [d] "{w1}" (w),
    );
    return c;
}

/// IEEE CRC-32 on 64 bits; matches `CRC32X` in Go's `crc32_arm64.s`.
fn crc32x_asm(crc: u32, data: u64) u32 {
    var c = crc;
    asm volatile ("crc32x w0, w0, x1"
        : [c] "+{w0}" (c),
        : [d] "{x1}" (data),
    );
    return c;
}

fn crc32w_asm(crc: u32, data: u32) u32 {
    var c = crc;
    asm volatile ("crc32w w0, w0, w1"
        : [c] "+{w0}" (c),
        : [d] "{w1}" (data),
    );
    return c;
}

fn crc32h_asm(crc: u32, data: u16) u32 {
    var c = crc;
    const w: u32 = data;
    asm volatile ("crc32h w0, w0, w1"
        : [c] "+{w0}" (c),
        : [d] "{w1}" (w),
    );
    return c;
}

fn crc32b_asm(crc: u32, data: u8) u32 {
    var c = crc;
    const w: u32 = data;
    asm volatile ("crc32b w0, w0, w1"
        : [c] "+{w0}" (c),
        : [d] "{w1}" (w),
    );
    return c;
}

fn castagnoliUpdate(crc: u32, p: []const u8) u32 {
    var acc = crc;
    var off: usize = 0;
    const len = p.len;

    while (off + 16 <= len) {
        const lo = std.mem.readInt(u64, p[off..][0..8], .little);
        const hi = std.mem.readInt(u64, p[off..][8..16], .little);
        acc = crc32cx_asm(acc, lo);
        acc = crc32cx_asm(acc, hi);
        off += 16;
    }

    const n = len - off;
    if (n == 0) return acc;

    var tail: [*]const u8 = p.ptr + off;

    if (n & 8 != 0) {
        const v = std.mem.readInt(u64, tail[0..8], .little);
        acc = crc32cx_asm(acc, v);
        tail += 8;
    }
    if (n & 4 != 0) {
        const v = std.mem.readInt(u32, tail[0..4], .little);
        acc = crc32cw_asm(acc, v);
        tail += 4;
    }
    if (n & 2 != 0) {
        const v = std.mem.readInt(u16, tail[0..2], .little);
        acc = crc32ch_asm(acc, v);
        tail += 2;
    }
    if (n & 1 != 0) {
        acc = crc32cb_asm(acc, tail[0]);
    }
    return acc;
}

fn ieeeUpdate(crc: u32, p: []const u8) u32 {
    var acc = crc;
    var off: usize = 0;
    const len = p.len;

    while (off + 16 <= len) {
        const lo = std.mem.readInt(u64, p[off..][0..8], .little);
        const hi = std.mem.readInt(u64, p[off..][8..16], .little);
        acc = crc32x_asm(acc, lo);
        acc = crc32x_asm(acc, hi);
        off += 16;
    }

    const n = len - off;
    if (n == 0) return acc;

    var tail: [*]const u8 = p.ptr + off;

    if (n & 8 != 0) {
        const v = std.mem.readInt(u64, tail[0..8], .little);
        acc = crc32x_asm(acc, v);
        tail += 8;
    }
    if (n & 4 != 0) {
        const v = std.mem.readInt(u32, tail[0..4], .little);
        acc = crc32w_asm(acc, v);
        tail += 4;
    }
    if (n & 2 != 0) {
        const v = std.mem.readInt(u16, tail[0..2], .little);
        acc = crc32h_asm(acc, v);
        tail += 2;
    }
    if (n & 1 != 0) {
        acc = crc32b_asm(acc, tail[0]);
    }
    return acc;
}

/// CRC-32C (Castagnoli) using `crc32c*` instructions; bitwise equivalent to `generic.simpleUpdate` for that polynomial.
pub fn archUpdateCastagnoli(crc: u32, p: []const u8) u32 {
    return ~castagnoliUpdate(~crc, p);
}

/// CRC-32 IEEE using `crc32*` instructions; bitwise equivalent to `generic.simpleUpdate` for IEEE.
pub fn archUpdateIEEE(crc: u32, p: []const u8) u32 {
    return ~ieeeUpdate(~crc, p);
}

test "ieeeUpdate archUpdateIEEE golden" {
    const t = generic.simpleMakeTable(generic.ieee_poly);
    try std.testing.expectEqual(@as(u32, 0), archUpdateIEEE(0, ""));
    try std.testing.expectEqual(@as(u32, 0xcbf43926), archUpdateIEEE(0, "123456789"));
    try std.testing.expectEqual(generic.simpleUpdate(0, &t, "123456789"), archUpdateIEEE(0, "123456789"));
}

test "archUpdateIEEE matches simpleUpdate IEEE" {
    const t = generic.simpleMakeTable(generic.ieee_poly);
    const inputs = [_][]const u8{
        "",
        "a",
        "hello",
        "1234567890123456",
        "123456789012345678901234567890",
    };
    for (inputs) |data| {
        try std.testing.expectEqual(
            generic.simpleUpdate(0, &t, data),
            archUpdateIEEE(0, data),
        );
        try std.testing.expectEqual(
            generic.simpleUpdate(0xffff_ffff, &t, data),
            archUpdateIEEE(0xffff_ffff, data),
        );
    }
}

test "ieeeUpdate tail lengths after 16-byte block" {
    const t = generic.simpleMakeTable(generic.ieee_poly);
    var prefix: [16]u8 = undefined;
    @memset(&prefix, 0x5a);
    var tail: [15]u8 = undefined;
    for (1..16) |k| {
        var buf: [31]u8 = undefined;
        @memcpy(buf[0..16], &prefix);
        for (0..k) |i| {
            tail[i] = @truncate(i + 0x30);
        }
        @memcpy(buf[16..][0..k], tail[0..k]);
        const slice: []const u8 = buf[0 .. 16 + k];
        try std.testing.expectEqual(
            generic.simpleUpdate(0, &t, slice),
            archUpdateIEEE(0, slice),
        );
    }
}
