//! Adler-32 checksum as used in zlib (RFC 1950): rolling sum over byte streams.
//!
//! **Not** a cryptographic hash. For transport integrity under adversaries, use a MAC or
//! authenticated encryption. Golden vectors align with Go `hash/adler32` where applicable.
//!
//! **Writer:** [`Adler32.writer`] uses [`std.Io.Writer.Hashing`]; call [`Writer.flush`](https://ziglang.org/documentation/master/std/#std.Io.Writer.flush)
//! after the last write before reading [`sum32`] or [`sum`].
const std = @import("std");
const hash_interface = @import("hash.zig");

const Writer = std.Io.Writer;

/// Incremental Adler-32 state. Default after [`reset`] is `1` (empty string checksum convention).
///
/// Use [`checksum`] for one-shot hashing. For [`hash_interface.Hash`], call [`hash`]; that facade
/// does not expose [`sum32`] — use the concrete type or read digest bytes from [`sum`] (big-endian
/// four-byte tail after `prefix`).
pub const Adler32 = struct {
    const AdlerHasher = struct {
        adler: *Adler32,
        pub fn update(self: *AdlerHasher, buf: []const u8) void {
            self.adler.digest = roll(self.adler.digest, buf);
        }
    };

    digest: u32,
    hash_writer: Writer.Hashing(AdlerHasher) = undefined,
    io_buf: [256]u8 = undefined,

    const Size = 4;
    const mod = 65521;
    /// Largest chunk processed before applying `% 65521` to both halves (zlib-style deferral).
    pub const max_chunk_len_before_mod = 5552;
    const magic = "adl\x01";
    const marshaledSize = magic.len + Size;

    /// Returns initial state (`digest == 1`).
    pub inline fn new() Adler32 {
        var adler32: Adler32 = undefined;
        adler32.reset();
        return adler32;
    }

    /// Constructs a value with an arbitrary intermediate `digest` (low 16 bits = s1, high 16 = s2).
    pub inline fn fromDigest(digest: u32) Adler32 {
        return .{ .digest = digest };
    }

    /// Restores the empty-string state (`digest = 1`).
    pub inline fn reset(self: *Adler32) void {
        self.digest = 1;
    }

    /// Vtable hook for [`hash_interface.Hash.reset`]; prefer [`reset`] on a known [`Adler32`].
    pub fn resetCast(ptr: *anyopaque) void {
        const self: *Adler32 = @ptrCast(@alignCast(ptr));
        reset(self);
    }

    /// Digest length in bytes (always 4).
    pub inline fn size(self: *const Adler32) usize {
        _ = self;
        return Size;
    }

    /// Vtable hook for [`hash_interface.Hash.size`].
    pub fn sizeCast(ptr: *anyopaque) usize {
        const self: *const Adler32 = @ptrCast(@alignCast(ptr));
        return size(self);
    }

    /// Hint value `4` (matches Go `hash.Hash` block size reporting for Adler-32).
    pub inline fn blockSize(self: *const Adler32) usize {
        _ = self;
        return 4;
    }

    /// Vtable hook for [`hash_interface.Hash.blockSize`].
    pub fn blockSizeCast(ptr: *anyopaque) usize {
        const self: *const Adler32 = @ptrCast(@alignCast(ptr));
        return blockSize(self);
    }

    /// Hashing writer; **flush** after the last write before reading the digest.
    pub fn writer(self: *Adler32) *Writer {
        self.hash_writer = .initHasher(.{ .adler = self }, self.io_buf[0..]);
        return &self.hash_writer.writer;
    }

    /// Vtable hook for [`hash_interface.Hash.writer`].
    pub fn writerCast(ptr: *anyopaque) *Writer {
        const self: *Adler32 = @ptrCast(@alignCast(ptr));
        return writer(self);
    }

    /// Type-erased [`hash_interface.Hash`] (digest via [`sum`] only; no [`sum32`] on the facade).
    pub fn hash(self: *Adler32) hash_interface.Hash {
        return .{
            .data = @ptrCast(self),
            .blockSizeFn = blockSizeCast,
            .resetFn = resetCast,
            .sizeFn = sizeCast,
            .sumFn = sumCast,
            .writerFn = writerCast,
        };
    }

    /// Allocates `data.len + 4` bytes: copies `data`, then appends digest **big-endian** (MSB first).
    /// Caller frees. Does not change state.
    pub fn sum(self: *const Adler32, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        const new_buffer = try allocator.alloc(u8, data.len + 4);
        errdefer allocator.free(new_buffer);

        const s = self.digest;

        const data_len = data.len;

        std.mem.copyForwards(u8, new_buffer[0..data_len], data);

        new_buffer[data_len] = @as(u8, @truncate(s >> 24));
        new_buffer[data_len + 1] = @as(u8, @truncate(s >> 16));
        new_buffer[data_len + 2] = @as(u8, @truncate(s >> 8));
        new_buffer[data_len + 3] = @as(u8, @truncate(s));

        return new_buffer;
    }

    /// Vtable hook for [`hash_interface.Hash.sum`].
    pub fn sumCast(ptr: *anyopaque, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        const self: *const Adler32 = @ptrCast(@alignCast(ptr));
        return sum(self, allocator, data);
    }

    /// Current digest as a single `u32` (s2 in high 16 bits, s1 in low 16 bits).
    pub inline fn sum32(self: *const Adler32) u32 {
        return self.digest;
    }

    /// Helper for a hypothetical [`hash_interface.Hash32`] binding; [`hash`] uses [`Hash`] and does not reference this.
    pub fn sum32Cast(ptr: *anyopaque) u32 {
        const self: *const Adler32 = @ptrCast(@alignCast(ptr));
        return sum32(self);
    }

    fn roll(digest: u32, p: []const u8) u32 {
        var p_start: usize = 0;
        var p_end = p.len;

        var q_start: usize = 0;
        var q_end: usize = 0;

        var s1 = digest & 0xffff;
        var s2 = digest >> 16;

        while (p_end - p_start > 0) {
            if ((p_end - p_start) > max_chunk_len_before_mod) {
                q_start = p_start + max_chunk_len_before_mod;
                q_end = p_end;

                p_end = p_start + max_chunk_len_before_mod;
            } else {
                q_start = 0;
                q_end = 0;
            }

            while (p_end - p_start >= 4) {
                s1 += @as(u32, p[p_start + 0]);
                s2 += s1;
                s1 += @as(u32, p[p_start + 1]);
                s2 += s1;
                s1 += @as(u32, p[p_start + 2]);
                s2 += s1;
                s1 += @as(u32, p[p_start + 3]);
                s2 += s1;
                p_start += 4;
            }

            for (p[p_start..p_end]) |x| {
                s1 += @as(u32, x);
                s2 += s1;
            }

            s1 %= mod;
            s2 %= mod;

            p_start = q_start;
            p_end = q_end;
        }

        return s2 << 16 | s1;
    }

    /// One-shot checksum of `data` starting from initial state (`1`).
    pub inline fn checksum(data: []const u8) u32 {
        return roll(1, data);
    }
};

const testing = std.testing;
const std_hash = std.hash.Adler32;

inline fn checksumExpect(want: u32, input: []const u8) !void {
    const got = Adler32.checksum(input);
    try testing.expectEqual(want, got);
}

fn expectSumLayout(digest: u32, prefix: []const u8, allocator: std.mem.Allocator) !void {
    const a = Adler32.fromDigest(digest);
    const got = try a.sum(allocator, prefix);
    defer allocator.free(got);
    try testing.expectEqual(prefix.len + 4, got.len);
    try testing.expectEqualSlices(u8, prefix, got[0..prefix.len]);
    const s = digest;
    try testing.expectEqual(@as(u8, @truncate(s >> 24)), got[prefix.len + 0]);
    try testing.expectEqual(@as(u8, @truncate(s >> 16)), got[prefix.len + 1]);
    try testing.expectEqual(@as(u8, @truncate(s >> 8)), got[prefix.len + 2]);
    try testing.expectEqual(@as(u8, @truncate(s)), got[prefix.len + 3]);
}

fn patternBuffer(allocator: std.mem.Allocator, len: usize, fill: u8) ![]u8 {
    const buf = try allocator.alloc(u8, len);
    @memset(buf, fill);
    return buf;
}

fn allocRepeatByteSuffix(allocator: std.mem.Allocator, byte: u8, count: usize, suffix: []const u8) ![]u8 {
    const buf = try allocator.alloc(u8, count + suffix.len);
    @memset(buf[0..count], byte);
    @memcpy(buf[count..], suffix);
    return buf;
}

fn allocRepeatPattern(allocator: std.mem.Allocator, pattern: []const u8, repeat: usize) ![]u8 {
    const total = try std.math.mul(usize, pattern.len, repeat);
    const buf = try allocator.alloc(u8, total);
    var off: usize = 0;
    for (0..repeat) |_| {
        @memcpy(buf[off..][0..pattern.len], pattern);
        off += pattern.len;
    }
    return buf;
}

test "checksum empty" {
    try checksumExpect(1, "");
}

test "checksum std vectors sanity" {
    try checksumExpect(0x620062, "a");
    try checksumExpect(0xbc002ed, "example");
}

test "checksum std vectors long" {
    const long1 = [_]u8{1} ** 1024;
    try checksumExpect(0x06780401, long1[0..]);

    const long2 = [_]u8{1} ** 1025;
    try checksumExpect(0x0a7a0402, long2[0..]);
}

test "checksum std vectors very long" {
    const long = [_]u8{1} ** 5553;
    try checksumExpect(0x707f15b2, long[0..]);
}

test "checksum very long with variation" {
    const long = comptime blk: {
        @setEvalBranchQuota(7000);
        var result: [6000]u8 = undefined;
        var i: usize = 0;
        while (i < result.len) : (i += 1) {
            result[i] = @as(u8, @truncate(i));
        }
        break :blk result;
    };
    try checksumExpect(0x5af38d6e, long[0..]);
}

test "checksum boundaries around max_chunk_len_before_mod" {
    const allocator = testing.allocator;
    inline for ([_]usize{ Adler32.max_chunk_len_before_mod, Adler32.max_chunk_len_before_mod + 1, 2 * Adler32.max_chunk_len_before_mod }) |len| {
        const buf = try patternBuffer(allocator, len, 0x01);
        defer allocator.free(buf);
        const want = std_hash.hash(buf);
        const got = Adler32.checksum(buf);
        try testing.expectEqual(want, got);
    }
}

test "checksum matches std.hash.Adler32 on short random lengths" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xfeed);
    const random = prng.random();
    var len: usize = 0;
    while (len < 256) : (len += 1) {
        const buf = try allocator.alloc(u8, len);
        defer allocator.free(buf);
        random.bytes(buf);
        const want = std_hash.hash(buf);
        const got = Adler32.checksum(buf);
        try testing.expectEqual(want, got);
    }
}

test "sum layout" {
    const allocator = testing.allocator;
    try expectSumLayout(1, "", allocator);
    try expectSumLayout(0x01020304, "", allocator);
    try expectSumLayout(0xdeadbeef, "hello", allocator);
    try expectSumLayout(0, "abc", allocator);
}

test "sum32 and reset" {
    var a: Adler32 = .new();
    try testing.expectEqual(@as(u32, 1), a.sum32());
    a.reset();
    try testing.expectEqual(@as(u32, 1), a.sum32());
}

test "size and blockSize" {
    const a: Adler32 = .new();
    try testing.expectEqual(@as(usize, 4), a.size());
    try testing.expectEqual(@as(usize, 4), a.blockSize());
}

test "Hash.sum matches Adler32.sum" {
    const allocator = testing.allocator;
    var a = Adler32.fromDigest(0x01020304);
    const h = a.hash();
    const via_hash = try h.sum(allocator, "abc");
    defer allocator.free(via_hash);
    const direct = try a.sum(allocator, "abc");
    defer allocator.free(direct);
    try testing.expectEqualSlices(u8, direct, via_hash);
}

test "Hash.size and Hash.blockSize match direct" {
    var a: Adler32 = .new();
    const h = a.hash();
    try testing.expectEqual(a.size(), h.size());
    try testing.expectEqual(a.blockSize(), h.blockSize());
}

test "writer writeAll matches checksum" {
    const input = " Discard medicine more than two years old.";
    var a = Adler32.new();
    var w = a.writer();
    try w.writeAll(input);
    try w.flush();
    try testing.expectEqual(Adler32.checksum(input), a.sum32());
}

test "writer chunked writes match checksum" {
    const input = "hello world example payload";
    var a = Adler32.new();
    var w = a.writer();
    try w.writeAll(input[0..5]);
    try w.writeAll(input[5..11]);
    try w.writeAll(input[11..]);
    try w.flush();
    try testing.expectEqual(Adler32.checksum(input), a.sum32());
}

test "Hash.writer matches direct writer" {
    const input = "abc";
    var direct = Adler32.new();
    var dw = direct.writer();
    try dw.writeAll(input);
    try dw.flush();
    var via = Adler32.new();
    const h = via.hash();
    var hw = h.writer();
    try hw.writeAll(input);
    try hw.flush();
    try testing.expectEqual(direct.sum32(), via.sum32());
    try testing.expectEqual(Adler32.checksum(input), via.sum32());
}

// Vectors from Go: hash/adler32/adler32_test.go (TestGolden golden table).
test "checksum go golden literals" {
    const cases = [_]struct { want: u32, in: []const u8 }{
        .{ .want = 0x00000001, .in = "" },
        .{ .want = 0x00620062, .in = "a" },
        .{ .want = 0x012600c4, .in = "ab" },
        .{ .want = 0x024d0127, .in = "abc" },
        .{ .want = 0x03d8018b, .in = "abcd" },
        .{ .want = 0x05c801f0, .in = "abcde" },
        .{ .want = 0x081e0256, .in = "abcdef" },
        .{ .want = 0x0adb02bd, .in = "abcdefg" },
        .{ .want = 0x0e000325, .in = "abcdefgh" },
        .{ .want = 0x118e038e, .in = "abcdefghi" },
        .{ .want = 0x158603f8, .in = "abcdefghij" },
        .{ .want = 0x3f090f02, .in = "Discard medicine more than two years old." },
        .{ .want = 0x46d81477, .in = "He who has a shady past knows that nice guys finish last." },
        .{ .want = 0x40ee0ee1, .in = "I wouldn't marry him with a ten foot pole." },
        .{ .want = 0x16661315, .in = "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" },
        .{ .want = 0x5b2e1480, .in = "The days of the digital watch are numbered.  -Tom Stoppard" },
        .{ .want = 0x8c3c09ea, .in = "Nepal premier won't resign." },
        .{ .want = 0x45ac18fd, .in = "For every action there is an equal and opposite government program." },
        .{ .want = 0x53c61462, .in = "His money is twice tainted: 'taint yours and 'taint mine." },
        .{ .want = 0x7e511e63, .in = "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" },
        .{ .want = 0xe4801a6a, .in = "It's a tiny change to the code and not completely disgusting. - Bob Manchek" },
        .{ .want = 0x61b507df, .in = "size:  a.out:  bad magic" },
        .{ .want = 0xb8631171, .in = "The major problem is with sendmail.  -Mark Horton" },
        .{ .want = 0x8b5e1904, .in = "Give me a rock, paper and scissors and I will move the world.  CCFestoon" },
        .{ .want = 0x7cc6102b, .in = "If the enemy is within range, then so are you." },
        .{ .want = 0x700318e7, .in = "It's well we cannot hear the screams/That we create in others' dreams." },
        .{ .want = 0x1e601747, .in = "You remind me of a TV show, but that's all right: I watch it anyway." },
        .{ .want = 0xb55b0b09, .in = "C is as portable as Stonehedge!!" },
        .{ .want = 0x39111dd0, .in = "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" },
        .{ .want = 0x91dd304f, .in = "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" },
        .{ .want = 0x2e5d1316, .in = "How can you write a big system without C++?  -Paul Glick" },
        .{ .want = 0xd0201df6, .in = "'Invariant assertions' is the most elegant programming technique!  -Tom Szymanski" },
    };
    for (cases) |case| {
        try checksumExpect(case.want, case.in);
    }
}

test "checksum go golden ff repeat edge" {
    const allocator = testing.allocator;
    const cases = [_]struct { want: u32, n: usize, tail: []const u8 }{
        .{ .want = 0x211297c8, .n = 5548, .tail = "8" },
        .{ .want = 0xbaa198c8, .n = 5549, .tail = "9" },
        .{ .want = 0x553499be, .n = 5550, .tail = "0" },
        .{ .want = 0xf0c19abe, .n = 5551, .tail = "1" },
        .{ .want = 0x8d5c9bbe, .n = 5552, .tail = "2" },
        .{ .want = 0x2af69cbe, .n = 5553, .tail = "3" },
        .{ .want = 0xc9809dbe, .n = 5554, .tail = "4" },
        .{ .want = 0x69189ebe, .n = 5555, .tail = "5" },
    };
    inline for (cases) |case| {
        const buf = try allocRepeatByteSuffix(allocator, 0xff, case.n, case.tail);
        defer allocator.free(buf);
        const got = Adler32.checksum(buf);
        try testing.expectEqual(case.want, got);
    }
}

test "checksum go golden huge" {
    const allocator = testing.allocator;
    {
        const buf = try allocRepeatPattern(allocator, &[_]u8{0}, 100_000);
        defer allocator.free(buf);
        try testing.expectEqual(@as(u32, 0x86af0001), Adler32.checksum(buf));
    }
    {
        const buf = try allocRepeatPattern(allocator, "a", 100_000);
        defer allocator.free(buf);
        try testing.expectEqual(@as(u32, 0x79660b4d), Adler32.checksum(buf));
    }
    {
        const buf = try allocRepeatPattern(allocator, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 10_000);
        defer allocator.free(buf);
        try testing.expectEqual(@as(u32, 0x110588ee), Adler32.checksum(buf));
    }
}
