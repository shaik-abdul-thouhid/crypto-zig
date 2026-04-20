//! CRC-32 checksums; API shaped like Go [`hash/crc32`](https://pkg.go.dev/hash/crc32).
//!
//! ## Polynomials
//!
//! - **IEEE** (a.k.a. PKZIP, Ethernet): default for ZIP, PNG, etc.
//! - **Castagnoli** (CRC-32C): common in storage and protobuf.
//!
//! ## Fast path vs software
//!
//! On **aarch64** with the **CRC** feature, [`updateIEEE`] and [`updateCastagnoli`] use
//! [`arch/aarch64.zig`](arch/aarch64.zig) intrinsics. Otherwise they use slicing-by-8 software tables
//! built from [`generic`].
//!
//! ## `update` vs `updateIEEE`
//!
//! [`update`] chooses the fast path when `tab` is **pointer-equal** to [`ieeeTable()`] (same table
//! object). Custom tables from [`generic.simpleMakeTable`] always use the byte-at-a-time
//! [`generic.simpleUpdate`] path.
//!
//! ## Security
//!
//! CRC-32 is not a cryptographic hash; do not use alone for authentication.
const std = @import("std");
const builtin = @import("builtin");

/// Software table construction and slicing-by-8 update; polynomial constants.
pub const generic = @import("generic.zig");

pub const Table = generic.Table;
pub const Slicing8Table = generic.Slicing8Table;

/// The size of a CRC-32 checksum in bytes (same as Go `crc32.Size`).
pub const size: usize = 4;

/// LSB-first polynomial, same as Go `crc32.IEEE`.
pub const IEEE = generic.ieee_poly;
/// Castagnoli polynomial, same as Go `crc32.Castagnoli`.
pub const Castagnoli = generic.castagnoli_poly;

var ieee_table_mem: Table = undefined;
var ieee_table_initiated: bool = false;

/// Canonical IEEE table (same role as Go `IEEETable`). Lazily initialized.
pub fn ieeeTable() *const Table {
    if (!ieee_table_initiated) {
        generic.simplePopulateTable(IEEE, &ieee_table_mem);
        ieee_table_initiated = true;
    }
    return &ieee_table_mem;
}

/// Reports whether a hardware-accelerated CRC32-IEEE implementation is used for this target
/// (same role as Go `archAvailableIEEE`).
pub inline fn archAvailableIEEE() bool {
    return builtin.cpu.arch == .aarch64 and builtin.cpu.has(.aarch64, .crc);
}

/// Reports whether a hardware-accelerated CRC32-C (Castagnoli) implementation is used.
/// Same role as Go `archAvailableCastagnoli`.
pub inline fn archAvailableCastagnoli() bool {
    return builtin.cpu.arch == .aarch64 and builtin.cpu.has(.aarch64, .crc);
}

var ieee_table8: Slicing8Table = undefined;
var ieee_table8_init: bool = false;

fn ieeeSlicingTable() *const Slicing8Table {
    if (!ieee_table8_init) {
        generic.slicingMakeTable(&ieee_table8, IEEE);
        ieee_table8_init = true;
    }
    return &ieee_table8;
}

var castagnoli_table8: Slicing8Table = undefined;
var castagnoli_table8_init: bool = false;

fn castagnoliSlicingTable() *const Slicing8Table {
    if (!castagnoli_table8_init) {
        generic.slicingMakeTable(&castagnoli_table8, Castagnoli);
        castagnoli_table8_init = true;
    }
    return &castagnoli_table8;
}

/// Initializes software tables when no HW CRC is available (Go `archInitIEEE` / `ieeeInitOnce`).
/// Safe to call multiple times; on HW targets this only prepares the slicing fallback if needed.
pub fn archInitIEEE() void {
    if (!archAvailableIEEE()) {
        _ = ieeeSlicingTable();
    }
}

/// Same for Castagnoli (Go `archInitCastagnoli` / `castagnoliInitOnce`).
pub fn archInitCastagnoli() void {
    if (!archAvailableCastagnoli()) {
        _ = castagnoliSlicingTable();
    }
}

/// Updates CRC-32 IEEE (same role as Go’s `updateIEEE` after init).
pub fn updateIEEE(crc: u32, p: []const u8) u32 {
    if (archAvailableIEEE()) {
        const arch = @import("arch/aarch64.zig");
        return arch.archUpdateIEEE(crc, p);
    }
    return generic.slicingUpdate(crc, ieeeSlicingTable(), p);
}

/// Updates CRC-32 Castagnoli (same role as Go’s `updateCastagnoli` after init).
pub fn updateCastagnoli(crc: u32, p: []const u8) u32 {
    if (archAvailableCastagnoli()) {
        const arch = @import("arch/aarch64.zig");
        return arch.archUpdateCastagnoli(crc, p);
    }
    return generic.slicingUpdate(crc, castagnoliSlicingTable(), p);
}

/// CRC-32 IEEE checksum of `data` (Go `ChecksumIEEE`).
pub fn checksumIEEE(data: []const u8) u32 {
    return updateIEEE(0, data);
}

/// CRC-32 Castagnoli checksum of `data`.
pub fn checksumCastagnoli(data: []const u8) u32 {
    return updateCastagnoli(0, data);
}

/// Updates `crc` with `p` using the given table (Go `Update` for arbitrary polynomials).
pub fn update(crc: u32, tab: *const Table, p: []const u8) u32 {
    if (tab == ieeeTable()) {
        return updateIEEE(crc, p);
    }
    return generic.simpleUpdate(crc, tab, p);
}

/// Checksum using an arbitrary polynomial table (Go `Checksum`).
pub fn checksum(data: []const u8, tab: *const Table) u32 {
    return update(0, tab, data);
}

/// Architecture-specific implementation module, or [`generic`] when no fast path exists.
pub const CRC32 = switch (builtin.cpu.arch) {
    .aarch64 => if (builtin.cpu.has(.aarch64, .crc)) @import("arch/aarch64.zig") else generic,
    else => generic,
};

test {
    _ = generic;
    _ = CRC32;
}

test "package updateIEEE matches generic.simpleUpdate for IEEE table" {
    const tab = ieeeTable();
    try std.testing.expectEqual(
        generic.simpleUpdate(0, tab, ""),
        updateIEEE(0, ""),
    );
    try std.testing.expectEqual(
        generic.simpleUpdate(0, tab, "123456789"),
        updateIEEE(0, "123456789"),
    );
    try std.testing.expectEqual(
        generic.simpleUpdate(0xffff_ffff, tab, "hello"),
        updateIEEE(0xffff_ffff, "hello"),
    );
}

test "package updateCastagnoli matches generic.simpleUpdate" {
    var tab: Table = undefined;
    generic.simplePopulateTable(Castagnoli, &tab);
    try std.testing.expectEqual(
        generic.simpleUpdate(0, &tab, ""),
        updateCastagnoli(0, ""),
    );
    try std.testing.expectEqual(
        generic.simpleUpdate(0, &tab, "abcdefgh"),
        updateCastagnoli(0, "abcdefgh"),
    );
}

test "checksumIEEE checksumCastagnoli" {
    try std.testing.expectEqual(updateIEEE(0, "x"), checksumIEEE("x"));
    var tab: Table = undefined;
    generic.simplePopulateTable(Castagnoli, &tab);
    try std.testing.expectEqual(generic.simpleUpdate(0, &tab, "y"), checksumCastagnoli("y"));
}
