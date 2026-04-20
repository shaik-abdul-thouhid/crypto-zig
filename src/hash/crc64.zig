//! CRC-64 checksums; API aligned with Go [`hash/crc64`](https://pkg.go.dev/hash/crc64).
//!
//! ## Polynomials
//!
//! - **`ISO`** — ISO 3309 / HDLC / `crc64` default in many tools.
//! - **`ECMA`** — ECMA-182 (a.k.a. ECMA polynomial).
//!
//! Use [`isoTable`] and [`ecmaTable`] for the precomputed tables. [`makeTable`] builds a table for an
//! arbitrary 64-bit polynomial (reflected form, same as Go `MakeTable`).
//!
//! ## Update paths
//!
//! [`simpleUpdate`] is the reference byte-at-a-time implementation. [`update`] uses slicing-by-8 for
//! long inputs on the built-in ISO/ECMA tables, and for custom tables when length ≥ 2048 (after
//! building a local slicing table).
//!
//! ## `Digest` and marshal
//!
//! [`Digest`] streams data with a fixed [`Table`] pointer. Binary marshal (`crc\x02` + [`tableSum`]
//! of table + current crc) ties state to a specific table; [`unmarshalBinary`] returns `TableMismatch`
//! if the table fingerprint does not match.
//!
//! ## Security
//!
//! CRC-64 is not cryptographic. **Writer:** call **`flush`** after buffered writes before reading the digest.
const std = @import("std");
const hash_interface = @import("hash.zig");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const assert = std.debug.assert;

pub const Table = [256]u64;

/// Checksum size in bytes (Go `crc64.Size`).
pub const size: usize = 8;

pub const ISO = 0xD800000000000000;
pub const ECMA = 0xC96C5795D7870F42;

const magic = "crc\x02";
pub const marshaled_size: usize = magic.len + 8 + 8;

pub const slicing8_iso: [8]Table = makeSlicing8Table(&makeTable(ISO));
pub const slicing8_ecma: [8]Table = makeSlicing8Table(&makeTable(ECMA));

/// Returns the ISO 3309 lookup table (same as Go `MakeTable(ISO)` / first row of slicing-by-8).
pub fn isoTable() *const Table {
    return &slicing8_iso[0];
}

/// Returns the ECMA-182 lookup table (same as Go `MakeTable(ECMA)`).
pub fn ecmaTable() *const Table {
    return &slicing8_ecma[0];
}

/// Build a 256-entry byte table for reflected polynomial `poly` (Go `MakeTable`).
pub fn makeTable(poly: u64) Table {
    @setEvalBranchQuota(10_000);
    var t: Table = undefined;
    for (0..256) |i| {
        var crc: u64 = @truncate(i);
        for (0..8) |_| {
            if (crc & 1 == 1) {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }
        t[i] = crc;
    }
    return t;
}

fn makeSlicing8Table(t: *const Table) [8]Table {
    @setEvalBranchQuota(30_000);
    var slicing8: [8]Table = undefined;
    slicing8[0] = t.*;
    for (0..256) |i| {
        var crc = t[i];
        for (1..8) |j| {
            crc = t[crc & 0xFF] ^ (crc >> 8);
            slicing8[j][i] = crc;
        }
    }
    return slicing8;
}

/// Byte-at-a-time update (reference; same as Go tail loop).
pub fn simpleUpdate(crc_in: u64, tab: *const Table, p: []const u8) u64 {
    var crc = ~crc_in;
    for (p) |v| {
        crc = tab[@as(u8, @truncate(crc)) ^ v] ^ (crc >> 8);
    }
    return ~crc;
}

fn slicingConsume(crc: *u64, tab: *const Table, p: []const u8, helper: *const [8]Table) []const u8 {
    var q = p;
    while (q.len > 8) {
        crc.* ^= std.mem.readInt(u64, q[0..8][0..8], .little);
        crc.* = helper[7][crc.* & 0xff] ^
            helper[6][(crc.* >> 8) & 0xff] ^
            helper[5][(crc.* >> 16) & 0xff] ^
            helper[4][(crc.* >> 24) & 0xff] ^
            helper[3][(crc.* >> 32) & 0xff] ^
            helper[2][(crc.* >> 40) & 0xff] ^
            helper[1][(crc.* >> 48) & 0xff] ^
            helper[0][crc.* >> 56];
        q = q[8..];
    }
    _ = tab;
    return q;
}

/// Updates CRC with `p` using `tab` (Go `Update`). Uses fast paths when `tab` is [`isoTable`], [`ecmaTable`], or long custom input.
pub fn update(crc_in: u64, tab: *const Table, p: []const u8) u64 {
    var crc = ~crc_in;
    var rest = p;

    while (rest.len >= 64) {
        if (tab == isoTable()) {
            rest = slicingConsume(&crc, tab, rest, &slicing8_iso);
        } else if (tab == ecmaTable()) {
            rest = slicingConsume(&crc, tab, rest, &slicing8_ecma);
        } else if (rest.len >= 2048) {
            var h: [8]Table = makeSlicing8Table(tab);
            rest = slicingConsume(&crc, tab, rest, &h);
        } else {
            break;
        }
    }

    for (rest) |v| {
        crc = tab[@as(u8, @truncate(crc)) ^ v] ^ (crc >> 8);
    }

    return ~crc;
}

/// CRC-64 checksum of `data` (Go `Checksum`).
pub fn checksum(data: []const u8, tab: *const Table) u64 {
    return update(0, tab, data);
}

/// Fingerprint of `tab`: CRC-64 (ISO) over the big-endian serialization of all 256 table entries (Go `tableSum`).
pub fn tableSum(tab: *const Table) u64 {
    var buf: [256 * 8]u8 = undefined;
    var i: usize = 0;
    for (tab.*) |x| {
        std.mem.writeInt(u64, buf[i..][0..8], x, .big);
        i += 8;
    }
    return checksum(buf[0..], isoTable());
}

/// Incremental CRC-64 over a fixed [`Table`] (polynomial chosen at construction).
pub const Digest = struct {
    const Crc64Hasher = struct {
        digest: *Digest,
        pub fn update(self: *Crc64Hasher, buf: []const u8) void {
            self.digest.write(buf);
        }
    };

    crc: u64,
    tab: *const Table,
    hash_writer: Writer.Hashing(Crc64Hasher) = undefined,
    buf: [256]u8 = undefined,

    /// Initial state (crc = 0) for `tab`.
    pub fn init(tab: *const Table) Digest {
        return .{ .crc = 0, .tab = tab };
    }

    /// Reset rolling crc to initial value; does not change `tab`.
    pub fn reset(self: *Digest) void {
        self.crc = 0;
    }

    /// Absorb bytes (Go `Write`).
    pub fn write(self: *Digest, p: []const u8) void {
        self.crc = update(self.crc, self.tab, p);
    }

    /// Current digest as `u64` (matches big-endian [`sum`] tail).
    pub fn sum64(self: *const Digest) u64 {
        return self.crc;
    }

    /// Allocates `prefix` then digest **big-endian** (8 bytes). Caller frees.
    pub fn sum(self: *const Digest, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        const s = self.crc;
        const base = prefix.len;
        out[base + 0] = @truncate(s >> 56);
        out[base + 1] = @truncate(s >> 48);
        out[base + 2] = @truncate(s >> 40);
        out[base + 3] = @truncate(s >> 32);
        out[base + 4] = @truncate(s >> 24);
        out[base + 5] = @truncate(s >> 16);
        out[base + 6] = @truncate(s >> 8);
        out[base + 7] = @truncate(s);
        return out;
    }

    /// `prefix`, then magic `crc\x02`, then `tableSum(self.tab)` and `self.crc` as big-endian `u64` (Go `AppendBinary`).
    pub fn appendBinary(self: *const Digest, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + marshaled_size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        const i = prefix.len;
        @memcpy(out[i..][0..magic.len], magic);
        std.mem.writeInt(u64, out[i + magic.len ..][0..8], tableSum(self.tab), .big);
        std.mem.writeInt(u64, out[i + magic.len + 8 ..][0..8], self.crc, .big);
        return out;
    }

    /// Serialized state (empty prefix [`appendBinary`]).
    pub fn marshalBinary(self: *const Digest, allocator: Allocator) Allocator.Error![]u8 {
        return appendBinary(self, allocator, &.{});
    }

    /// Restore crc from [`marshalBinary`] output; **`TableMismatch`** if `self.tab` does not match embedded table fingerprint.
    pub fn unmarshalBinary(self: *Digest, b: []const u8) error{ InvalidIdentifier, InvalidSize, TableMismatch }!void {
        if (b.len < magic.len or !std.mem.eql(u8, b[0..magic.len], magic)) {
            return error.InvalidIdentifier;
        }
        if (b.len != marshaled_size) {
            return error.InvalidSize;
        }
        const want_sum = std.mem.readInt(u64, b[4..12], .big);
        if (tableSum(self.tab) != want_sum) {
            return error.TableMismatch;
        }
        self.crc = std.mem.readInt(u64, b[12..20], .big);
    }

    /// Vtable: [`hash_interface.Hash64.reset`].
    pub fn resetCast(ptr: *anyopaque) void {
        const s: *Digest = @ptrCast(@alignCast(ptr));
        s.reset();
    }

    /// Vtable: [`hash_interface.Hash64.size`].
    pub fn sizeCast(_: *anyopaque) usize {
        return size;
    }

    /// Vtable: [`hash_interface.Hash64.blockSize`].
    pub fn blockSizeCast(_: *anyopaque) usize {
        return 1;
    }

    /// Vtable: [`hash_interface.Hash64.sum`].
    pub fn sumCast(ptr: *anyopaque, allocator: Allocator, data: []const u8) ![]u8 {
        const s: *const Digest = @ptrCast(@alignCast(ptr));
        return s.sum(allocator, data);
    }

    /// Vtable: [`hash_interface.Hash64.sum64`].
    pub fn sum64Cast(ptr: *anyopaque) u64 {
        const s: *const Digest = @ptrCast(@alignCast(ptr));
        return s.sum64();
    }

    /// Hashing writer; **flush** after the last write so buffered bytes are folded into the CRC.
    pub fn writer(self: *Digest) *Writer {
        self.hash_writer = .initHasher(.{ .digest = self }, self.buf[0..]);
        return &self.hash_writer.writer;
    }

    /// Vtable: [`hash_interface.Hash64.writer`].
    pub fn writerCast(ptr: *anyopaque) *Writer {
        const s: *Digest = @ptrCast(@alignCast(ptr));
        return writer(s);
    }

    /// Type-erased [`hash_interface.Hash64`].
    pub fn hash64(self: *Digest) hash_interface.Hash64 {
        return .{
            .data = @ptrCast(self),
            .sumFn = sumCast,
            .resetFn = resetCast,
            .sizeFn = sizeCast,
            .blockSizeFn = blockSizeCast,
            .sum64Fn = sum64Cast,
            .writerFn = writerCast,
        };
    }
};

/// Alias for [`Digest.init`].
pub fn new(tab: *const Table) Digest {
    return Digest.init(tab);
}

const testing = std.testing;

test "update matches simpleUpdate small inputs ISO" {
    const tab = isoTable();
    const inputs: []const []const u8 = &.{ "", "a", "hello", "1234567890" };
    for (inputs) |inp| {
        try testing.expectEqual(simpleUpdate(0, tab, inp), update(0, tab, inp));
    }
}

test "update matches simpleUpdate small inputs ECMA" {
    const tab = ecmaTable();
    const inputs: []const []const u8 = &.{ "", "x", "hello world" };
    for (inputs) |inp| {
        try testing.expectEqual(simpleUpdate(0, tab, inp), update(0, tab, inp));
    }
}

test "slicing path matches simpleUpdate ISO long" {
    const tab = isoTable();
    var buf: [500]u8 = undefined;
    for (0..buf.len) |i| buf[i] = @truncate(i);
    try testing.expectEqual(simpleUpdate(0, tab, &buf), update(0, tab, &buf));
}

test "custom polynomial long input uses slicing when len >= 2048" {
    var tab: Table = makeTable(0x777);
    try testing.expectEqual(simpleUpdate(0, &tab, &[_]u8{}), update(0, &tab, &[_]u8{}));
    var buf: [2500]u8 = undefined;
    @memset(&buf, 0x5a);
    try testing.expectEqual(simpleUpdate(0, &tab, &buf), update(0, &tab, &buf));
}

// Golden vectors from Go: hash/crc64/crc64_test.go (var golden).
test "checksum go golden" {
    const cases = [_]struct { out_iso: u64, out_ecma: u64, in: []const u8 }{
        .{ .out_iso = 0x0, .out_ecma = 0x0, .in = "" },
        .{ .out_iso = 0x3420000000000000, .out_ecma = 0x330284772e652b05, .in = "a" },
        .{ .out_iso = 0x36c4200000000000, .out_ecma = 0xbc6573200e84b046, .in = "ab" },
        .{ .out_iso = 0x3776c42000000000, .out_ecma = 0x2cd8094a1a277627, .in = "abc" },
        .{ .out_iso = 0x336776c420000000, .out_ecma = 0x3c9d28596e5960ba, .in = "abcd" },
        .{ .out_iso = 0x32d36776c4200000, .out_ecma = 0x40bdf58fb0895f2, .in = "abcde" },
        .{ .out_iso = 0x3002d36776c42000, .out_ecma = 0xd08e9f8545a700f4, .in = "abcdef" },
        .{ .out_iso = 0x31b002d36776c420, .out_ecma = 0xec20a3a8cc710e66, .in = "abcdefg" },
        .{ .out_iso = 0xe21b002d36776c4, .out_ecma = 0x67b4f30a647a0c59, .in = "abcdefgh" },
        .{ .out_iso = 0x8b6e21b002d36776, .out_ecma = 0x9966f6c89d56ef8e, .in = "abcdefghi" },
        .{ .out_iso = 0x7f5b6e21b002d367, .out_ecma = 0x32093a2ecd5773f4, .in = "abcdefghij" },
        .{ .out_iso = 0x8ec0e7c835bf9cdf, .out_ecma = 0x8a0825223ea6d221, .in = "Discard medicine more than two years old." },
        .{ .out_iso = 0xc7db1759e2be5ab4, .out_ecma = 0x8562c0ac2ab9a00d, .in = "He who has a shady past knows that nice guys finish last." },
        .{ .out_iso = 0xfbf9d9603a6fa020, .out_ecma = 0x3ee2a39c083f38b4, .in = "I wouldn't marry him with a ten foot pole." },
        .{ .out_iso = 0xeafc4211a6daa0ef, .out_ecma = 0x1f603830353e518a, .in = "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" },
        .{ .out_iso = 0x3e05b21c7a4dc4da, .out_ecma = 0x2fd681d7b2421fd, .in = "The days of the digital watch are numbered.  -Tom Stoppard" },
        .{ .out_iso = 0x5255866ad6ef28a6, .out_ecma = 0x790ef2b16a745a41, .in = "Nepal premier won't resign." },
        .{ .out_iso = 0x8a79895be1e9c361, .out_ecma = 0x3ef8f06daccdcddf, .in = "For every action there is an equal and opposite government program." },
        .{ .out_iso = 0x8878963a649d4916, .out_ecma = 0x49e41b2660b106d, .in = "His money is twice tainted: 'taint yours and 'taint mine." },
        .{ .out_iso = 0xa7b9d53ea87eb82f, .out_ecma = 0x561cc0cfa235ac68, .in = "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" },
        .{ .out_iso = 0xdb6805c0966a2f9c, .out_ecma = 0xd4fe9ef082e69f59, .in = "It's a tiny change to the code and not completely disgusting. - Bob Manchek" },
        .{ .out_iso = 0xf3553c65dacdadd2, .out_ecma = 0xe3b5e46cd8d63a4d, .in = "size:  a.out:  bad magic" },
        .{ .out_iso = 0x9d5e034087a676b9, .out_ecma = 0x865aaf6b94f2a051, .in = "The major problem is with sendmail.  -Mark Horton" },
        .{ .out_iso = 0xa6db2d7f8da96417, .out_ecma = 0x7eca10d2f8136eb4, .in = "Give me a rock, paper and scissors and I will move the world.  CCFestoon" },
        .{ .out_iso = 0x325e00cd2fe819f9, .out_ecma = 0xd7dd118c98e98727, .in = "If the enemy is within range, then so are you." },
        .{ .out_iso = 0x88c6600ce58ae4c6, .out_ecma = 0x70fb33c119c29318, .in = "It's well we cannot hear the screams/That we create in others' dreams." },
        .{ .out_iso = 0x28c4a3f3b769e078, .out_ecma = 0x57c891e39a97d9b7, .in = "You remind me of a TV show, but that's all right: I watch it anyway." },
        .{ .out_iso = 0xa698a34c9d9f1dca, .out_ecma = 0xa1f46ba20ad06eb7, .in = "C is as portable as Stonehedge!!" },
        .{ .out_iso = 0xf6c1e2a8c26c5cfc, .out_ecma = 0x7ad25fafa1710407, .in = "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" },
        .{ .out_iso = 0xd402559dfe9b70c, .out_ecma = 0x73cef1666185c13f, .in = "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" },
        .{ .out_iso = 0xdb6efff26aa94946, .out_ecma = 0xb41858f73c389602, .in = "How can you write a big system without C++?  -Paul Glick" },
        .{ .out_iso = 0xe7fcf1006b503b61, .out_ecma = 0x27db187fc15bbc72, .in = "This is a test of the emergency broadcast system." },
    };

    for (cases) |g| {
        try testing.expectEqual(g.out_iso, checksum(g.in, isoTable()));
        try testing.expectEqual(g.out_ecma, checksum(g.in, ecmaTable()));
    }
}

// Hex-encoded MarshalBinary output after digesting first half of input (Go TestGoldenMarshal).
test "marshal golden half-state" {
    const inputs = [_][]const u8{
        "",
        "a",
        "ab",
        "abc",
        "abcd",
        "abcde",
        "abcdef",
        "abcdefg",
        "abcdefgh",
        "abcdefghi",
        "abcdefghij",
        "Discard medicine more than two years old.",
        "He who has a shady past knows that nice guys finish last.",
        "I wouldn't marry him with a ten foot pole.",
        "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave",
        "The days of the digital watch are numbered.  -Tom Stoppard",
        "Nepal premier won't resign.",
        "For every action there is an equal and opposite government program.",
        "His money is twice tainted: 'taint yours and 'taint mine.",
        "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
        "It's a tiny change to the code and not completely disgusting. - Bob Manchek",
        "size:  a.out:  bad magic",
        "The major problem is with sendmail.  -Mark Horton",
        "Give me a rock, paper and scissors and I will move the world.  CCFestoon",
        "If the enemy is within range, then so are you.",
        "It's well we cannot hear the screams/That we create in others' dreams.",
        "You remind me of a TV show, but that's all right: I watch it anyway.",
        "C is as portable as Stonehedge!!",
        "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley",
        "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule",
        "How can you write a big system without C++?  -Paul Glick",
        "This is a test of the emergency broadcast system.",
    };

    const golden_iso_hex = [_][]const u8{
        "6372630273ba8484bbcd5def0000000000000000",
        "6372630273ba8484bbcd5def0000000000000000",
        "6372630273ba8484bbcd5def3420000000000000",
        "6372630273ba8484bbcd5def3420000000000000",
        "6372630273ba8484bbcd5def36c4200000000000",
        "6372630273ba8484bbcd5def36c4200000000000",
        "6372630273ba8484bbcd5def3776c42000000000",
        "6372630273ba8484bbcd5def3776c42000000000",
        "6372630273ba8484bbcd5def336776c420000000",
        "6372630273ba8484bbcd5def336776c420000000",
        "6372630273ba8484bbcd5def32d36776c4200000",
        "6372630273ba8484bbcd5defc6c00cac271112d5",
        "6372630273ba8484bbcd5def09cbd135585b7209",
        "6372630273ba8484bbcd5def19c864be8414875f",
        "6372630273ba8484bbcd5defad1b2ac0b1f36928",
        "6372630273ba8484bbcd5def7637381a6b028fff",
        "6372630273ba8484bbcd5defcb661152bf68dec9",
        "6372630273ba8484bbcd5deff3705601635f5775",
        "6372630273ba8484bbcd5defc3b1fff1e02fce94",
        "6372630273ba8484bbcd5defddb861e1b5f8b957",
        "6372630273ba8484bbcd5def56ba1291811f4e55",
        "6372630273ba8484bbcd5def47adbcb2a879c9dc",
        "6372630273ba8484bbcd5defa2ac6e8a543b26d5",
        "6372630273ba8484bbcd5defeb18bff97d91e57c",
        "6372630273ba8484bbcd5def5e356bd0416a5f7b",
        "6372630273ba8484bbcd5def7cb502dc77182f86",
        "6372630273ba8484bbcd5def038b641cb05f1698",
        "6372630273ba8484bbcd5def2e50e149c67069dc",
        "6372630273ba8484bbcd5deff7a0348af26fe03b",
        "6372630273ba8484bbcd5def7faeb9ba583d1976",
        "6372630273ba8484bbcd5def61ed246a73b9a541",
        "6372630273ba8484bbcd5def7dee5b7116cbe48d",
    };

    const golden_ecma_hex = [_][]const u8{
        "6372630260269a52e1b7fe650000000000000000",
        "6372630260269a52e1b7fe650000000000000000",
        "6372630260269a52e1b7fe65330284772e652b05",
        "6372630260269a52e1b7fe65330284772e652b05",
        "6372630260269a52e1b7fe65bc6573200e84b046",
        "6372630260269a52e1b7fe65bc6573200e84b046",
        "6372630260269a52e1b7fe652cd8094a1a277627",
        "6372630260269a52e1b7fe652cd8094a1a277627",
        "6372630260269a52e1b7fe653c9d28596e5960ba",
        "6372630260269a52e1b7fe653c9d28596e5960ba",
        "6372630260269a52e1b7fe65040bdf58fb0895f2",
        "6372630260269a52e1b7fe65fd25c026a052ef95",
        "6372630260269a52e1b7fe650702e87c2bc106e3",
        "6372630260269a52e1b7fe65cbb7d3ee47dc458c",
        "6372630260269a52e1b7fe65a78adbf6d2520996",
        "6372630260269a52e1b7fe6554cb6c10fb874b2a",
        "6372630260269a52e1b7fe653613d98f065fbd9a",
        "6372630260269a52e1b7fe65e7c60a0812464ca0",
        "6372630260269a52e1b7fe654f4c2fb1eca21487",
        "6372630260269a52e1b7fe658729475103f44b09",
        "6372630260269a52e1b7fe650ab881763fde4ccb",
        "6372630260269a52e1b7fe65cccee5e6897001b8",
        "6372630260269a52e1b7fe6546669c1fc978bf61",
        "6372630260269a52e1b7fe65619e053ace5be719",
        "6372630260269a52e1b7fe650b2399a872835952",
        "6372630260269a52e1b7fe655d9d2ded8cf97239",
        "6372630260269a52e1b7fe65af5798aa22e7d77c",
        "6372630260269a52e1b7fe65d69a060128c01e8b",
        "6372630260269a52e1b7fe653c5bd2259e6d9404",
        "6372630260269a52e1b7fe65b2cba659c5d04703",
        "6372630260269a52e1b7fe655a6d968ae2af1370",
        "6372630260269a52e1b7fe65b1935d20eba9616d",
    };

    assert(inputs.len == golden_iso_hex.len);
    assert(inputs.len == golden_ecma_hex.len);

    for (inputs, golden_iso_hex) |inp, want_hex| {
        var h = Digest.init(isoTable());
        const half = inp[0 .. inp.len / 2];
        h.write(half);
        const got = try h.marshalBinary(testing.allocator);
        defer testing.allocator.free(got);

        var want_buf: [marshaled_size]u8 = undefined;
        const want = try std.fmt.hexToBytes(&want_buf, want_hex);
        try testing.expectEqualSlices(u8, want, got);
    }

    for (inputs, golden_ecma_hex) |inp, want_hex| {
        var h = Digest.init(ecmaTable());
        const half = inp[0 .. inp.len / 2];
        h.write(half);
        const got = try h.marshalBinary(testing.allocator);
        defer testing.allocator.free(got);

        var want_buf: [marshaled_size]u8 = undefined;
        const want = try std.fmt.hexToBytes(&want_buf, want_hex);
        try testing.expectEqualSlices(u8, want, got);
    }
}

test "marshal round-trip split write matches full checksum ISO" {
    const inputs = [_][]const u8{
        "",
        "a",
        "abcdefghij",
        "This is a test of the emergency broadcast system.",
    };

    for (inputs) |inp| {
        var h1 = Digest.init(isoTable());
        var h2 = Digest.init(isoTable());
        const mid = inp.len / 2;
        h1.write(inp[0..mid]);
        const state = try h1.marshalBinary(testing.allocator);
        defer testing.allocator.free(state);
        try h2.unmarshalBinary(state);
        h1.write(inp[mid..]);
        h2.write(inp[mid..]);
        try testing.expectEqual(h1.sum64(), h2.sum64());
        try testing.expectEqual(checksum(inp, isoTable()), h1.sum64());
    }
}

test "marshal table mismatch" {
    var h_iso = Digest.init(isoTable());
    h_iso.write("hello");
    const state = try h_iso.marshalBinary(testing.allocator);
    defer testing.allocator.free(state);

    var h_ecma = Digest.init(ecmaTable());
    try testing.expectError(error.TableMismatch, h_ecma.unmarshalBinary(state));
}

test "Hash64.sum64 matches digest" {
    var d = Digest.init(isoTable());
    d.write("abc");
    const hh = d.hash64();
    try testing.expectEqual(d.sum64(), hh.sum64());
}

test "Digest.writer ISO matches checksum" {
    const input = "hello crc64 iso writer path";
    var d = Digest.init(isoTable());
    var w = d.writer();
    try w.writeAll(input);
    try w.flush();
    try testing.expectEqual(checksum(input, isoTable()), d.sum64());
}

test "Digest.writer ECMA chunked matches checksum" {
    const input = "ECMA-182 chunk stream";
    var d = Digest.init(ecmaTable());
    var w = d.writer();
    try w.writeAll(input[0..8]);
    try w.writeAll(input[8..]);
    try w.flush();
    try testing.expectEqual(checksum(input, ecmaTable()), d.sum64());
}

test "Hash64.writer matches Digest.writer" {
    const input = "abc";
    var direct = Digest.init(isoTable());
    var dw = direct.writer();
    try dw.writeAll(input);
    try dw.flush();
    var via = Digest.init(isoTable());
    const h = via.hash64();
    var hw = h.writer();
    try hw.writeAll(input);
    try hw.flush();
    try testing.expectEqual(direct.sum64(), via.sum64());
    try testing.expectEqual(checksum(input, isoTable()), via.sum64());
}
