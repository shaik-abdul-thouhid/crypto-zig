//! Software CRC-32: table generation and byte-at-a-time / slicing-by-8 updates.
//!
//! Polynomials are **reflected** LSB-first forms (same as Go `MakeTable` / `simpleUpdate`):
//! [`ieee_poly`] and [`castagnoli_poly`]. These routines are the fallback when hardware CRC is
//! unavailable and the building blocks for custom polynomials.
const std = @import("std");

pub const Table = [256]u32;
pub const Slicing8Table = [8]Table;

/// Allocates and returns a new byte table for `poly` (reflected representation).
pub fn simpleMakeTable(poly: u32) Table {
    var t: Table = undefined;
    simplePopulateTable(poly, &t);

    return t;
}

/// Fills `t` with the byte-at-a-time CRC table for reflected polynomial `poly`.
pub fn simplePopulateTable(poly: u32, t: *Table) void {
    for (t, 0..) |*entry, i| {
        var crc: u32 = @truncate(i);
        for (0..8) |_| {
            if (crc & 1 == 1) {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }

        entry.* = crc;
    }
}

/// One-byte-at-a-time CRC update (Go `simpleUpdate`). `crc` is the running value **before** final inversion.
pub fn simpleUpdate(crc: u32, tab: *const Table, p: []const u8) u32 {
    var c = ~crc;
    for (p) |x| {
        c = tab[@as(u8, @truncate(c)) ^ x] ^ (c >> 8);
    }
    return ~c;
}

/// Minimum length of remaining input before [`slicingUpdate`] uses the slicing-by-8 loop.
pub const slicing8_cutoff: usize = 16;

/// In-place construction of a slicing-by-8 table for the given polynomial.
pub fn slicingMakeTable(slicing_table: *Slicing8Table, poly: u32) void {
    simplePopulateTable(poly, &slicing_table[0]);

    for (0..256) |i| {
        var crc = slicing_table[0][i];
        for (1..8) |j| {
            crc = slicing_table[0][crc & 0xFF] ^ (crc >> 8);
            slicing_table[j][i] = crc;
        }
    }
}

/// Slicing-by-8 update; matches Go `hash/crc32.slicingUpdate` (crc32_generic.go).
pub fn slicingUpdate(crc: u32, tab: *const Slicing8Table, p: []const u8) u32 {
    var c = crc;
    var buf = p;
    if (buf.len >= slicing8_cutoff) {
        c = ~c;
        while (buf.len > 8) {
            c ^= @as(u32, buf[0]) | (@as(u32, buf[1]) << 8) | (@as(u32, buf[2]) << 16) | (@as(u32, buf[3]) << 24);
            c = tab[0][buf[7]] ^ tab[1][buf[6]] ^ tab[2][buf[5]] ^ tab[3][buf[4]] ^
                tab[4][(c >> 24) & 0xFF] ^ tab[5][(c >> 16) & 0xFF] ^
                tab[6][(c >> 8) & 0xFF] ^ tab[7][c & 0xFF];
            buf = buf[8..];
        }
        c = ~c;
    }
    if (buf.len == 0) return c;
    return simpleUpdate(c, &tab[0], buf);
}

/// Reflected IEEE polynomial (Go `crc32.IEEE`).
pub const ieee_poly: u32 = 0xedb88320;

/// Reflected Castagnoli polynomial (Go `crc32.Castagnoli`).
pub const castagnoli_poly: u32 = 0x82f63b78;

test "simple table IEEE spot checks" {
    const t = simpleMakeTable(ieee_poly);
    try std.testing.expectEqual(@as(u32, 0), t[0]);
    try std.testing.expectEqual(@as(u32, 0x77073096), t[1]);
    try std.testing.expectEqual(@as(u32, 755167117), t[255]);
}

test "simpleUpdate IEEE golden" {
    const t = simpleMakeTable(ieee_poly);
    try std.testing.expectEqual(@as(u32, 0), simpleUpdate(0, &t, ""));
    try std.testing.expectEqual(@as(u32, 0xcbf43926), simpleUpdate(0, &t, "123456789"));
}

test "slicingUpdate matches simpleUpdate" {
    var st: Slicing8Table = undefined;
    slicingMakeTable(&st, ieee_poly);

    const inputs = [_][]const u8{
        "",
        "a",
        "hello",
        "1234567890123456",
        "123456789012345678901234567890",
    };

    for (inputs) |data| {
        try std.testing.expectEqual(
            simpleUpdate(0, &st[0], data),
            slicingUpdate(0, &st, data),
        );
        try std.testing.expectEqual(
            simpleUpdate(0xffff_ffff, &st[0], data),
            slicingUpdate(0xffff_ffff, &st, data),
        );
    }
}
