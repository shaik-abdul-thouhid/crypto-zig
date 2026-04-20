//! Fowler–Noll–Vo (FNV-1 and FNV-1a) non-cryptographic hashes for 32-, 64-, and 128-bit digests.
//!
//! Constants, update rules, digest **big-endian** layout in [`sum`], and binary marshal magics match
//! Go [`hash/fnv`](https://pkg.go.dev/hash/fnv). **Not** suitable for security; trivial collisions are easy.
//!
//! **128-bit state:** two `u64` halves `[0]` (high) and `[1]` (low); [`sum`] writes one big-endian `u128`
//! `(s[0] << 64) | s[1]`. **Writer:** call [`Writer.flush`](https://ziglang.org/documentation/master/std/#std.Io.Writer.flush)
//! after buffered writes before reading the digest.
//!
//! **Vtable hooks** on each hasher (`resetCast`, `sizeCast`, `blockSizeCast`, `sumCast`, `sum32Cast` / `sum64Cast`,
//! `writerCast`) exist for [`hash_interface`] integration; prefer the typed methods when the concrete type is known.
const std = @import("std");
const hash_interface = @import("hash.zig");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

pub const offset32: u32 = 2166136261;

pub const offset64: u64 = 14695981039346656037;

pub const offset128_high: u64 = 0x6c62272e07bb0142;

pub const offset128_low: u64 = 0x62b821756295c58d;

pub const prime32: u32 = 16777619;
pub const prime64: u64 = 1099511628211;
pub const prime128_lower: u64 = 0x13b;
pub const prime128_shift: u6 = 24;

fn fnv128_step_1(s: *[2]u64, p: []const u8) void {
    for (p) |c| {
        const in0 = s[0];
        const in1 = s[1];
        const prod: u128 = @as(u128, in1) * @as(u128, prime128_lower);
        const mul_lo = @as(u64, @truncate(prod));
        const mul_hi = @as(u64, @truncate(prod >> 64));
        var acc = mul_hi;
        acc +%= (in1 << prime128_shift) +% (prime128_lower *% in0);
        s[1] = mul_lo;
        s[0] = acc;
        s[1] ^= @as(u64, c);
    }
}

fn fnv128_step_1a(s: *[2]u64, p: []const u8) void {
    for (p) |c| {
        s[1] ^= @as(u64, c);
        const in0 = s[0];
        const in1 = s[1];
        const prod: u128 = @as(u128, in1) * @as(u128, prime128_lower);
        const mul_lo = @as(u64, @truncate(prod));
        const mul_hi = @as(u64, @truncate(prod >> 64));
        var acc = mul_hi;
        acc +%= (in1 << prime128_shift) +% (prime128_lower *% in0);
        s[1] = mul_lo;
        s[0] = acc;
    }
}

/// FNV-1, 32-bit. Digest in [`sum`] is **big-endian** four bytes; [`sum32`] is the native `u32` value.
/// Marshal magic: `fnv\x01` + big-endian state (Go `MarshalBinary`).
pub const Fnv32 = struct {
    const Hasher = struct {
        h: *Fnv32,
        pub fn update(self: *Hasher, buf: []const u8) void {
            self.h.write(buf);
        }
    };

    state: u32,
    hash_writer: Writer.Hashing(Hasher) = undefined,
    io_buf: [256]u8 = undefined,

    /// Digest length in bytes (`4`).
    pub const size: usize = 4;
    const magic = "fnv\x01";
    const marshaled_size = magic.len + size;

    /// Initial FNV-1 state ([`offset32`]).
    pub fn new() Fnv32 {
        return .{ .state = offset32 };
    }

    /// Reset to [`offset32`].
    pub fn reset(self: *Fnv32) void {
        self.state = offset32;
    }

    /// Absorb bytes (FNV-1: multiply by prime, then xor byte).
    pub fn write(self: *Fnv32, p: []const u8) void {
        var h = self.state;
        for (p) |c| {
            h *%= prime32;
            h ^= @as(u32, c);
        }
        self.state = h;
    }

    /// Current digest as `u32` (matches big-endian [`sum`] tail).
    pub fn sum32(self: *const Fnv32) u32 {
        return self.state;
    }

    /// Allocates `prefix` followed by digest **big-endian** (4 bytes). Caller frees.
    pub fn sum(self: *const Fnv32, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        const v = self.state;
        std.mem.writeInt(u32, out[prefix.len..][0..4], v, .big);
        return out;
    }

    /// `prefix` + magic + big-endian state (Go `AppendBinary`).
    pub fn appendBinary(self: *const Fnv32, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + marshaled_size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        const i = prefix.len;
        @memcpy(out[i..][0..magic.len], magic);
        std.mem.writeInt(u32, out[i + magic.len ..][0..4], self.state, .big);
        return out;
    }

    /// Serialized state only (same as `appendBinary` with empty prefix).
    pub fn marshalBinary(self: *const Fnv32, allocator: Allocator) Allocator.Error![]u8 {
        return appendBinary(self, allocator, &.{});
    }

    /// Restores from [`marshalBinary`] output; errors on wrong magic or length.
    pub fn unmarshalBinary(self: *Fnv32, b: []const u8) error{ InvalidIdentifier, InvalidSize }!void {
        if (b.len < magic.len or !std.mem.eql(u8, b[0..magic.len], magic)) {
            return error.InvalidIdentifier;
        }
        if (b.len != marshaled_size) {
            return error.InvalidSize;
        }
        self.state = std.mem.readInt(u32, b[4..8], .big);
    }

    /// Hashing writer; **flush** before reading digest.
    pub fn writer(self: *Fnv32) *Writer {
        self.hash_writer = .initHasher(.{ .h = self }, self.io_buf[0..]);
        return &self.hash_writer.writer;
    }

    /// Vtable: [`hash_interface.Hash32.reset`].
    pub fn resetCast(ptr: *anyopaque) void {
        @as(*Fnv32, @ptrCast(@alignCast(ptr))).reset();
    }
    /// Vtable: [`hash_interface.Hash32.size`].
    pub fn sizeCast(_: *anyopaque) usize {
        return size;
    }
    /// Vtable: [`hash_interface.Hash32.blockSize`].
    pub fn blockSizeCast(_: *anyopaque) usize {
        return 1;
    }
    /// Vtable: [`hash_interface.Hash32.sum`].
    pub fn sumCast(ptr: *anyopaque, allocator: Allocator, data: []const u8) Allocator.Error![]u8 {
        const s: *const Fnv32 = @ptrCast(@alignCast(ptr));
        return s.sum(allocator, data);
    }
    /// Vtable: [`hash_interface.Hash32.sum32`].
    pub fn sum32Cast(ptr: *anyopaque) u32 {
        return @as(*const Fnv32, @ptrCast(@alignCast(ptr))).sum32();
    }
    /// Vtable: [`hash_interface.Hash32.writer`].
    pub fn writerCast(ptr: *anyopaque) *Writer {
        return @as(*Fnv32, @ptrCast(@alignCast(ptr))).writer();
    }

    /// Type-erased [`hash_interface.Hash32`] facade.
    pub fn hash32(self: *Fnv32) hash_interface.Hash32 {
        return .{
            .data = @ptrCast(self),
            .sumFn = sumCast,
            .resetFn = resetCast,
            .sizeFn = sizeCast,
            .blockSizeFn = blockSizeCast,
            .sum32Fn = sum32Cast,
            .writerFn = writerCast,
        };
    }
};

/// FNV-1a, 32-bit (xor then multiply). Same layout and marshal magic `fnv\x02` as Go `hash/fnv` `New32a`.
pub const Fnv32a = struct {
    const Hasher = struct {
        h: *Fnv32a,
        pub fn update(self: *Hasher, buf: []const u8) void {
            self.h.write(buf);
        }
    };

    state: u32,
    io: Writer.Hashing(Hasher) = undefined,
    io_buf: [256]u8 = undefined,

    pub const size: usize = 4;
    const magic = "fnv\x02";
    const marshaled_size = magic.len + size;

    pub fn new() Fnv32a {
        return .{ .state = offset32 };
    }

    pub fn reset(self: *Fnv32a) void {
        self.state = offset32;
    }

    /// FNV-1a: xor byte, then multiply by [`prime32`].
    pub fn write(self: *Fnv32a, p: []const u8) void {
        var h = self.state;
        for (p) |c| {
            h ^= @as(u32, c);
            h *%= prime32;
        }
        self.state = h;
    }

    pub fn sum32(self: *const Fnv32a) u32 {
        return self.state;
    }

    pub fn sum(self: *const Fnv32a, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        std.mem.writeInt(u32, out[prefix.len..][0..4], self.state, .big);
        return out;
    }

    pub fn appendBinary(self: *const Fnv32a, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + marshaled_size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        const i = prefix.len;
        @memcpy(out[i..][0..magic.len], magic);
        std.mem.writeInt(u32, out[i + magic.len ..][0..4], self.state, .big);
        return out;
    }

    pub fn marshalBinary(self: *const Fnv32a, allocator: Allocator) Allocator.Error![]u8 {
        return appendBinary(self, allocator, &.{});
    }

    pub fn unmarshalBinary(self: *Fnv32a, b: []const u8) error{ InvalidIdentifier, InvalidSize }!void {
        if (b.len < magic.len or !std.mem.eql(u8, b[0..magic.len], magic)) {
            return error.InvalidIdentifier;
        }
        if (b.len != marshaled_size) {
            return error.InvalidSize;
        }
        self.state = std.mem.readInt(u32, b[4..8], .big);
    }

    pub fn writer(self: *Fnv32a) *Writer {
        self.io = Writer.Hashing(Hasher).initHasher(.{ .h = self }, self.io_buf[0..]);
        return &self.io.writer;
    }

    /// Vtable: [`hash_interface.Hash32.reset`].
    pub fn resetCast(ptr: *anyopaque) void {
        @as(*Fnv32a, @ptrCast(@alignCast(ptr))).reset();
    }
    /// Vtable: [`hash_interface.Hash32.size`].
    pub fn sizeCast(_: *anyopaque) usize {
        return size;
    }
    /// Vtable: [`hash_interface.Hash32.blockSize`].
    pub fn blockSizeCast(_: *anyopaque) usize {
        return 1;
    }
    /// Vtable: [`hash_interface.Hash32.sum`].
    pub fn sumCast(ptr: *anyopaque, allocator: Allocator, data: []const u8) Allocator.Error![]u8 {
        return @as(*const Fnv32a, @ptrCast(@alignCast(ptr))).sum(allocator, data);
    }
    /// Vtable: [`hash_interface.Hash32.sum32`].
    pub fn sum32Cast(ptr: *anyopaque) u32 {
        return @as(*const Fnv32a, @ptrCast(@alignCast(ptr))).sum32();
    }
    /// Vtable: [`hash_interface.Hash32.writer`].
    pub fn writerCast(ptr: *anyopaque) *Writer {
        return @as(*Fnv32a, @ptrCast(@alignCast(ptr))).writer();
    }

    pub fn hash32(self: *Fnv32a) hash_interface.Hash32 {
        return .{
            .data = @ptrCast(self),
            .sumFn = sumCast,
            .resetFn = resetCast,
            .sizeFn = sizeCast,
            .blockSizeFn = blockSizeCast,
            .sum32Fn = sum32Cast,
            .writerFn = writerCast,
        };
    }
};

/// FNV-1, 64-bit. Digest in [`sum`] is **big-endian** eight bytes; [`sum64`] is native order value.
/// Marshal magic `fnv\x03` (Go `New64`). Methods match [`Fnv32`] semantics at 64-bit width.
pub const Fnv64 = struct {
    const Hasher = struct {
        h: *Fnv64,
        pub fn update(self: *Hasher, buf: []const u8) void {
            self.h.write(buf);
        }
    };

    state: u64,
    io: Writer.Hashing(Hasher) = undefined,
    io_buf: [256]u8 = undefined,

    /// Digest length in bytes (`8`).
    pub const size: usize = 8;
    const magic = "fnv\x03";
    const marshaled_size = magic.len + size;

    pub fn new() Fnv64 {
        return .{ .state = offset64 };
    }

    pub fn reset(self: *Fnv64) void {
        self.state = offset64;
    }

    pub fn write(self: *Fnv64, p: []const u8) void {
        var h = self.state;
        for (p) |c| {
            h *%= prime64;
            h ^= @as(u64, c);
        }
        self.state = h;
    }

    pub fn sum64(self: *const Fnv64) u64 {
        return self.state;
    }

    pub fn sum(self: *const Fnv64, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        std.mem.writeInt(u64, out[prefix.len..][0..8], self.state, .big);
        return out;
    }

    pub fn appendBinary(self: *const Fnv64, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + marshaled_size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        const i = prefix.len;
        @memcpy(out[i..][0..magic.len], magic);
        std.mem.writeInt(u64, out[i + magic.len ..][0..8], self.state, .big);
        return out;
    }

    pub fn marshalBinary(self: *const Fnv64, allocator: Allocator) Allocator.Error![]u8 {
        return appendBinary(self, allocator, &.{});
    }

    pub fn unmarshalBinary(self: *Fnv64, b: []const u8) error{ InvalidIdentifier, InvalidSize }!void {
        if (b.len < magic.len or !std.mem.eql(u8, b[0..magic.len], magic)) {
            return error.InvalidIdentifier;
        }
        if (b.len != marshaled_size) {
            return error.InvalidSize;
        }
        self.state = std.mem.readInt(u64, b[4..12], .big);
    }

    pub fn writer(self: *Fnv64) *Writer {
        self.io = Writer.Hashing(Hasher).initHasher(.{ .h = self }, self.io_buf[0..]);
        return &self.io.writer;
    }

    /// Vtable: [`hash_interface.Hash64.reset`].
    pub fn resetCast(ptr: *anyopaque) void {
        @as(*Fnv64, @ptrCast(@alignCast(ptr))).reset();
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
    pub fn sumCast(ptr: *anyopaque, allocator: Allocator, data: []const u8) Allocator.Error![]u8 {
        return @as(*const Fnv64, @ptrCast(@alignCast(ptr))).sum(allocator, data);
    }
    /// Vtable: [`hash_interface.Hash64.sum64`].
    pub fn sum64Cast(ptr: *anyopaque) u64 {
        return @as(*const Fnv64, @ptrCast(@alignCast(ptr))).sum64();
    }
    /// Vtable: [`hash_interface.Hash64.writer`].
    pub fn writerCast(ptr: *anyopaque) *Writer {
        return @as(*Fnv64, @ptrCast(@alignCast(ptr))).writer();
    }

    /// Type-erased [`hash_interface.Hash64`] facade.
    pub fn hash64(self: *Fnv64) hash_interface.Hash64 {
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

/// FNV-1a, 64-bit. Marshal magic `fnv\x04` (Go `New64a`). Same API shape as [`Fnv64`].
pub const Fnv64a = struct {
    const Hasher = struct {
        h: *Fnv64a,
        pub fn update(self: *Hasher, buf: []const u8) void {
            self.h.write(buf);
        }
    };

    state: u64,
    io: Writer.Hashing(Hasher) = undefined,
    io_buf: [256]u8 = undefined,

    pub const size: usize = 8;
    const magic = "fnv\x04";
    const marshaled_size = magic.len + size;

    pub fn new() Fnv64a {
        return .{ .state = offset64 };
    }

    pub fn reset(self: *Fnv64a) void {
        self.state = offset64;
    }

    pub fn write(self: *Fnv64a, p: []const u8) void {
        var h = self.state;
        for (p) |c| {
            h ^= @as(u64, c);
            h *%= prime64;
        }
        self.state = h;
    }

    pub fn sum64(self: *const Fnv64a) u64 {
        return self.state;
    }

    pub fn sum(self: *const Fnv64a, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        std.mem.writeInt(u64, out[prefix.len..][0..8], self.state, .big);
        return out;
    }

    pub fn appendBinary(self: *const Fnv64a, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + marshaled_size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        const i = prefix.len;
        @memcpy(out[i..][0..magic.len], magic);
        std.mem.writeInt(u64, out[i + magic.len ..][0..8], self.state, .big);
        return out;
    }

    pub fn marshalBinary(self: *const Fnv64a, allocator: Allocator) Allocator.Error![]u8 {
        return appendBinary(self, allocator, &.{});
    }

    pub fn unmarshalBinary(self: *Fnv64a, b: []const u8) error{ InvalidIdentifier, InvalidSize }!void {
        if (b.len < magic.len or !std.mem.eql(u8, b[0..magic.len], magic)) {
            return error.InvalidIdentifier;
        }
        if (b.len != marshaled_size) {
            return error.InvalidSize;
        }
        self.state = std.mem.readInt(u64, b[4..12], .big);
    }

    pub fn writer(self: *Fnv64a) *Writer {
        self.io = Writer.Hashing(Hasher).initHasher(.{ .h = self }, self.io_buf[0..]);
        return &self.io.writer;
    }

    /// Vtable: [`hash_interface.Hash64.reset`].
    pub fn resetCast(ptr: *anyopaque) void {
        @as(*Fnv64a, @ptrCast(@alignCast(ptr))).reset();
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
    pub fn sumCast(ptr: *anyopaque, allocator: Allocator, data: []const u8) Allocator.Error![]u8 {
        return @as(*const Fnv64a, @ptrCast(@alignCast(ptr))).sum(allocator, data);
    }
    /// Vtable: [`hash_interface.Hash64.sum64`].
    pub fn sum64Cast(ptr: *anyopaque) u64 {
        return @as(*const Fnv64a, @ptrCast(@alignCast(ptr))).sum64();
    }
    /// Vtable: [`hash_interface.Hash64.writer`].
    pub fn writerCast(ptr: *anyopaque) *Writer {
        return @as(*Fnv64a, @ptrCast(@alignCast(ptr))).writer();
    }

    pub fn hash64(self: *Fnv64a) hash_interface.Hash64 {
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

/// FNV-1, 128-bit. State `s[0]` then `s[1]` match Go `sum128` big-endian order. Marshal magic `fnv\x05`.
/// No `sum128` on [`hash_interface.Hash`]; use [`sum128`] on this struct or digest bytes from [`sum`].
pub const Fnv128 = struct {
    const Hasher = struct {
        h: *Fnv128,
        pub fn update(self: *Hasher, buf: []const u8) void {
            self.h.write(buf);
        }
    };

    s: [2]u64,
    io: Writer.Hashing(Hasher) = undefined,
    io_buf: [256]u8 = undefined,

    pub const size: usize = 16;
    const magic = "fnv\x05";
    const marshaled_size = magic.len + size;

    pub fn new() Fnv128 {
        return .{ .s = .{ offset128_high, offset128_low } };
    }

    pub fn reset(self: *Fnv128) void {
        self.s[0] = offset128_high;
        self.s[1] = offset128_low;
    }

    pub fn write(self: *Fnv128, p: []const u8) void {
        fnv128_step_1(&self.s, p);
    }

    pub fn sum128(self: *const Fnv128) [2]u64 {
        return self.s;
    }

    pub fn sum(self: *const Fnv128, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        std.mem.writeInt(u128, out[prefix.len..][0..16], @as(u128, self.s[0]) << 64 | @as(u128, self.s[1]), .big);
        return out;
    }

    pub fn appendBinary(self: *const Fnv128, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + marshaled_size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        const i = prefix.len;
        @memcpy(out[i..][0..magic.len], magic);
        std.mem.writeInt(u64, out[i + magic.len ..][0..8], self.s[0], .big);
        std.mem.writeInt(u64, out[i + magic.len + 8 ..][0..8], self.s[1], .big);
        return out;
    }

    pub fn marshalBinary(self: *const Fnv128, allocator: Allocator) Allocator.Error![]u8 {
        return appendBinary(self, allocator, &.{});
    }

    pub fn unmarshalBinary(self: *Fnv128, b: []const u8) error{ InvalidIdentifier, InvalidSize }!void {
        if (b.len < magic.len or !std.mem.eql(u8, b[0..magic.len], magic)) {
            return error.InvalidIdentifier;
        }
        if (b.len != marshaled_size) {
            return error.InvalidSize;
        }
        self.s[0] = std.mem.readInt(u64, b[4..12], .big);
        self.s[1] = std.mem.readInt(u64, b[12..20], .big);
    }

    pub fn writer(self: *Fnv128) *Writer {
        self.io = Writer.Hashing(Hasher).initHasher(.{ .h = self }, self.io_buf[0..]);
        return &self.io.writer;
    }

    /// Vtable: [`hash_interface.Hash.reset`].
    pub fn resetCast(ptr: *anyopaque) void {
        @as(*Fnv128, @ptrCast(@alignCast(ptr))).reset();
    }
    /// Vtable: [`hash_interface.Hash.size`].
    pub fn sizeCast(_: *anyopaque) usize {
        return size;
    }
    /// Vtable: [`hash_interface.Hash.blockSize`].
    pub fn blockSizeCast(_: *anyopaque) usize {
        return 1;
    }
    /// Vtable: [`hash_interface.Hash.sum`].
    pub fn sumCast(ptr: *anyopaque, allocator: Allocator, data: []const u8) Allocator.Error![]u8 {
        return @as(*const Fnv128, @ptrCast(@alignCast(ptr))).sum(allocator, data);
    }
    /// Vtable: [`hash_interface.Hash.writer`].
    pub fn writerCast(ptr: *anyopaque) *Writer {
        return @as(*Fnv128, @ptrCast(@alignCast(ptr))).writer();
    }

    /// Type-erased [`hash_interface.Hash`] (variable-width digest via [`sum`] only).
    pub fn hash(self: *Fnv128) hash_interface.Hash {
        return .{
            .data = @ptrCast(self),
            .sumFn = sumCast,
            .resetFn = resetCast,
            .sizeFn = sizeCast,
            .blockSizeFn = blockSizeCast,
            .writerFn = writerCast,
        };
    }
};

/// FNV-1a, 128-bit. Marshal magic `fnv\x06` (Go `New128a`).
pub const Fnv128a = struct {
    const Hasher = struct {
        h: *Fnv128a,
        pub fn update(self: *Hasher, buf: []const u8) void {
            self.h.write(buf);
        }
    };

    s: [2]u64,
    io: Writer.Hashing(Hasher) = undefined,
    io_buf: [256]u8 = undefined,

    pub const size: usize = 16;
    const magic = "fnv\x06";
    const marshaled_size = magic.len + size;

    pub fn new() Fnv128a {
        return .{ .s = .{ offset128_high, offset128_low } };
    }

    pub fn reset(self: *Fnv128a) void {
        self.s[0] = offset128_high;
        self.s[1] = offset128_low;
    }

    pub fn write(self: *Fnv128a, p: []const u8) void {
        fnv128_step_1a(&self.s, p);
    }

    pub fn sum128(self: *const Fnv128a) [2]u64 {
        return self.s;
    }

    pub fn sum(self: *const Fnv128a, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        std.mem.writeInt(u128, out[prefix.len..][0..16], @as(u128, self.s[0]) << 64 | @as(u128, self.s[1]), .big);
        return out;
    }

    pub fn appendBinary(self: *const Fnv128a, allocator: Allocator, prefix: []const u8) Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, prefix.len + marshaled_size);
        errdefer allocator.free(out);
        @memcpy(out[0..prefix.len], prefix);
        const i = prefix.len;
        @memcpy(out[i..][0..magic.len], magic);
        std.mem.writeInt(u64, out[i + magic.len ..][0..8], self.s[0], .big);
        std.mem.writeInt(u64, out[i + magic.len + 8 ..][0..8], self.s[1], .big);
        return out;
    }

    pub fn marshalBinary(self: *const Fnv128a, allocator: Allocator) Allocator.Error![]u8 {
        return appendBinary(self, allocator, &.{});
    }

    pub fn unmarshalBinary(self: *Fnv128a, b: []const u8) error{ InvalidIdentifier, InvalidSize }!void {
        if (b.len < magic.len or !std.mem.eql(u8, b[0..magic.len], magic)) {
            return error.InvalidIdentifier;
        }
        if (b.len != marshaled_size) {
            return error.InvalidSize;
        }
        self.s[0] = std.mem.readInt(u64, b[4..12], .big);
        self.s[1] = std.mem.readInt(u64, b[12..20], .big);
    }

    pub fn writer(self: *Fnv128a) *Writer {
        self.io = Writer.Hashing(Hasher).initHasher(.{ .h = self }, self.io_buf[0..]);
        return &self.io.writer;
    }

    /// Vtable: [`hash_interface.Hash.reset`].
    pub fn resetCast(ptr: *anyopaque) void {
        @as(*Fnv128a, @ptrCast(@alignCast(ptr))).reset();
    }
    /// Vtable: [`hash_interface.Hash.size`].
    pub fn sizeCast(_: *anyopaque) usize {
        return size;
    }
    /// Vtable: [`hash_interface.Hash.blockSize`].
    pub fn blockSizeCast(_: *anyopaque) usize {
        return 1;
    }
    /// Vtable: [`hash_interface.Hash.sum`].
    pub fn sumCast(ptr: *anyopaque, allocator: Allocator, data: []const u8) Allocator.Error![]u8 {
        return @as(*const Fnv128a, @ptrCast(@alignCast(ptr))).sum(allocator, data);
    }
    /// Vtable: [`hash_interface.Hash.writer`].
    pub fn writerCast(ptr: *anyopaque) *Writer {
        return @as(*Fnv128a, @ptrCast(@alignCast(ptr))).writer();
    }

    pub fn hash(self: *Fnv128a) hash_interface.Hash {
        return .{
            .data = @ptrCast(self),
            .sumFn = sumCast,
            .resetFn = resetCast,
            .sizeFn = sizeCast,
            .blockSizeFn = blockSizeCast,
            .writerFn = writerCast,
        };
    }
};

const testing = std.testing;

const Golden32 = struct { want: [4]u8, in: []const u8, half_marshal: [8]u8 };
const Golden64 = struct { want: [8]u8, in: []const u8, half_marshal: [12]u8 };
const Golden128 = struct { want: [16]u8, in: []const u8, half_marshal: [20]u8 };

fn testGolden32(h: *Fnv32, cases: []const Golden32) !void {
    for (cases) |g| {
        h.reset();
        h.write(g.in);
        const got = try h.sum(testing.allocator, &.{});
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &g.want, got);

        var h2 = Fnv32.new();
        h2.write(g.in[0 .. g.in.len / 2]);
        const state = try h2.marshalBinary(testing.allocator);
        defer testing.allocator.free(state);
        try testing.expectEqualSlices(u8, &g.half_marshal, state);

        const append_state = try h2.appendBinary(testing.allocator, &.{ 0, 0, 0, 0 });
        defer testing.allocator.free(append_state);
        try testing.expectEqualSlices(u8, &g.half_marshal, append_state[4..]);

        var h3 = Fnv32.new();
        try h3.unmarshalBinary(state);
        h2.write(g.in[g.in.len / 2 ..]);
        h3.write(g.in[g.in.len / 2 ..]);
        const a = try h2.sum(testing.allocator, &.{});
        defer testing.allocator.free(a);
        const b = try h3.sum(testing.allocator, &.{});
        defer testing.allocator.free(b);
        try testing.expectEqualSlices(u8, a, b);
    }
}

fn testGolden32a(h: *Fnv32a, cases: []const Golden32) !void {
    for (cases) |g| {
        h.reset();
        h.write(g.in);
        const got = try h.sum(testing.allocator, &.{});
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &g.want, got);

        var h2 = Fnv32a.new();
        h2.write(g.in[0 .. g.in.len / 2]);
        const state = try h2.marshalBinary(testing.allocator);
        defer testing.allocator.free(state);
        try testing.expectEqualSlices(u8, &g.half_marshal, state);

        const append_state = try h2.appendBinary(testing.allocator, &.{ 0, 0, 0, 0 });
        defer testing.allocator.free(append_state);
        try testing.expectEqualSlices(u8, &g.half_marshal, append_state[4..]);

        var h3 = Fnv32a.new();
        try h3.unmarshalBinary(state);
        h2.write(g.in[g.in.len / 2 ..]);
        h3.write(g.in[g.in.len / 2 ..]);
        const a = try h2.sum(testing.allocator, &.{});
        defer testing.allocator.free(a);
        const b = try h3.sum(testing.allocator, &.{});
        defer testing.allocator.free(b);
        try testing.expectEqualSlices(u8, a, b);
    }
}

fn testGolden64(h: *Fnv64, cases: []const Golden64) !void {
    for (cases) |g| {
        h.reset();
        h.write(g.in);
        const got = try h.sum(testing.allocator, &.{});
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &g.want, got);

        var h2 = Fnv64.new();
        h2.write(g.in[0 .. g.in.len / 2]);
        const state = try h2.marshalBinary(testing.allocator);
        defer testing.allocator.free(state);
        try testing.expectEqualSlices(u8, &g.half_marshal, state);

        const append_state = try h2.appendBinary(testing.allocator, &.{ 0, 0, 0, 0 });
        defer testing.allocator.free(append_state);
        try testing.expectEqualSlices(u8, &g.half_marshal, append_state[4..]);

        var h3 = Fnv64.new();
        try h3.unmarshalBinary(state);
        h2.write(g.in[g.in.len / 2 ..]);
        h3.write(g.in[g.in.len / 2 ..]);
        const a = try h2.sum(testing.allocator, &.{});
        defer testing.allocator.free(a);
        const b = try h3.sum(testing.allocator, &.{});
        defer testing.allocator.free(b);
        try testing.expectEqualSlices(u8, a, b);
    }
}

fn testGolden64a(h: *Fnv64a, cases: []const Golden64) !void {
    for (cases) |g| {
        h.reset();
        h.write(g.in);
        const got = try h.sum(testing.allocator, &.{});
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &g.want, got);

        var h2 = Fnv64a.new();
        h2.write(g.in[0 .. g.in.len / 2]);
        const state = try h2.marshalBinary(testing.allocator);
        defer testing.allocator.free(state);
        try testing.expectEqualSlices(u8, &g.half_marshal, state);

        const append_state = try h2.appendBinary(testing.allocator, &.{ 0, 0, 0, 0 });
        defer testing.allocator.free(append_state);
        try testing.expectEqualSlices(u8, &g.half_marshal, append_state[4..]);

        var h3 = Fnv64a.new();
        try h3.unmarshalBinary(state);
        h2.write(g.in[g.in.len / 2 ..]);
        h3.write(g.in[g.in.len / 2 ..]);
        const a = try h2.sum(testing.allocator, &.{});
        defer testing.allocator.free(a);
        const b = try h3.sum(testing.allocator, &.{});
        defer testing.allocator.free(b);
        try testing.expectEqualSlices(u8, a, b);
    }
}

fn testGolden128(h: *Fnv128, cases: []const Golden128) !void {
    for (cases) |g| {
        h.reset();
        h.write(g.in);
        const got = try h.sum(testing.allocator, &.{});
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &g.want, got);

        var h2 = Fnv128.new();
        h2.write(g.in[0 .. g.in.len / 2]);
        const state = try h2.marshalBinary(testing.allocator);
        defer testing.allocator.free(state);
        try testing.expectEqualSlices(u8, &g.half_marshal, state);

        const append_state = try h2.appendBinary(testing.allocator, &.{ 0, 0, 0, 0 });
        defer testing.allocator.free(append_state);
        try testing.expectEqualSlices(u8, &g.half_marshal, append_state[4..]);

        var h3 = Fnv128.new();
        try h3.unmarshalBinary(state);
        h2.write(g.in[g.in.len / 2 ..]);
        h3.write(g.in[g.in.len / 2 ..]);
        const a = try h2.sum(testing.allocator, &.{});
        defer testing.allocator.free(a);
        const b = try h3.sum(testing.allocator, &.{});
        defer testing.allocator.free(b);
        try testing.expectEqualSlices(u8, a, b);
    }
}

fn testGolden128a(h: *Fnv128a, cases: []const Golden128) !void {
    for (cases) |g| {
        h.reset();
        h.write(g.in);
        const got = try h.sum(testing.allocator, &.{});
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, &g.want, got);

        var h2 = Fnv128a.new();
        h2.write(g.in[0 .. g.in.len / 2]);
        const state = try h2.marshalBinary(testing.allocator);
        defer testing.allocator.free(state);
        try testing.expectEqualSlices(u8, &g.half_marshal, state);

        const append_state = try h2.appendBinary(testing.allocator, &.{ 0, 0, 0, 0 });
        defer testing.allocator.free(append_state);
        try testing.expectEqualSlices(u8, &g.half_marshal, append_state[4..]);

        var h3 = Fnv128a.new();
        try h3.unmarshalBinary(state);
        h2.write(g.in[g.in.len / 2 ..]);
        h3.write(g.in[g.in.len / 2 ..]);
        const a = try h2.sum(testing.allocator, &.{});
        defer testing.allocator.free(a);
        const b = try h3.sum(testing.allocator, &.{});
        defer testing.allocator.free(b);
        try testing.expectEqualSlices(u8, a, b);
    }
}

test "fnv golden 32" {
    var h = Fnv32.new();
    const cases = [_]Golden32{
        .{ .want = .{ 0x81, 0x1c, 0x9d, 0xc5 }, .in = "", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x01, 0x81, 0x1c, 0x9d, 0xc5 } },
        .{ .want = .{ 0x05, 0x0c, 0x5d, 0x7e }, .in = "a", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x01, 0x81, 0x1c, 0x9d, 0xc5 } },
        .{ .want = .{ 0x70, 0x77, 0x2d, 0x38 }, .in = "ab", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x01, 0x05, 0x0c, 0x5d, 0x7e } },
        .{ .want = .{ 0x43, 0x9c, 0x2f, 0x4b }, .in = "abc", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x01, 0x05, 0x0c, 0x5d, 0x7e } },
    };
    try testGolden32(&h, &cases);
}

test "fnv golden 32a" {
    var h = Fnv32a.new();
    const cases = [_]Golden32{
        .{ .want = .{ 0x81, 0x1c, 0x9d, 0xc5 }, .in = "", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x02, 0x81, 0x1c, 0x9d, 0xc5 } },
        .{ .want = .{ 0xe4, 0x0c, 0x29, 0x2c }, .in = "a", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x02, 0x81, 0x1c, 0x9d, 0xc5 } },
        .{ .want = .{ 0x4d, 0x25, 0x05, 0xca }, .in = "ab", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x02, 0xe4, 0x0c, 0x29, 0x2c } },
        .{ .want = .{ 0x1a, 0x47, 0xe9, 0x0b }, .in = "abc", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x02, 0xe4, 0x0c, 0x29, 0x2c } },
    };
    try testGolden32a(&h, &cases);
}

test "fnv golden 64" {
    var h = Fnv64.new();
    const cases = [_]Golden64{
        .{ .want = .{ 0xcb, 0xf2, 0x9c, 0xe4, 0x84, 0x22, 0x23, 0x25 }, .in = "", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x03, 0xcb, 0xf2, 0x9c, 0xe4, 0x84, 0x22, 0x23, 0x25 } },
        .{ .want = .{ 0xaf, 0x63, 0xbd, 0x4c, 0x86, 0x01, 0xb7, 0xbe }, .in = "a", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x03, 0xcb, 0xf2, 0x9c, 0xe4, 0x84, 0x22, 0x23, 0x25 } },
        .{ .want = .{ 0x08, 0x32, 0x67, 0x07, 0xb4, 0xeb, 0x37, 0xb8 }, .in = "ab", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x03, 0xaf, 0x63, 0xbd, 0x4c, 0x86, 0x01, 0xb7, 0xbe } },
        .{ .want = .{ 0xd8, 0xdc, 0xca, 0x18, 0x6b, 0xaf, 0xad, 0xcb }, .in = "abc", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x03, 0xaf, 0x63, 0xbd, 0x4c, 0x86, 0x01, 0xb7, 0xbe } },
    };
    try testGolden64(&h, &cases);
}

test "fnv golden 64a" {
    var h = Fnv64a.new();
    const cases = [_]Golden64{
        .{ .want = .{ 0xcb, 0xf2, 0x9c, 0xe4, 0x84, 0x22, 0x23, 0x25 }, .in = "", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x04, 0xcb, 0xf2, 0x9c, 0xe4, 0x84, 0x22, 0x23, 0x25 } },
        .{ .want = .{ 0xaf, 0x63, 0xdc, 0x4c, 0x86, 0x01, 0xec, 0x8c }, .in = "a", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x04, 0xcb, 0xf2, 0x9c, 0xe4, 0x84, 0x22, 0x23, 0x25 } },
        .{ .want = .{ 0x08, 0x9c, 0x44, 0x07, 0xb5, 0x45, 0x98, 0x6a }, .in = "ab", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x04, 0xaf, 0x63, 0xdc, 0x4c, 0x86, 0x01, 0xec, 0x8c } },
        .{ .want = .{ 0xe7, 0x1f, 0xa2, 0x19, 0x05, 0x41, 0x57, 0x4b }, .in = "abc", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x04, 0xaf, 0x63, 0xdc, 0x4c, 0x86, 0x01, 0xec, 0x8c } },
    };
    try testGolden64a(&h, &cases);
}

test "fnv golden 128" {
    var h = Fnv128.new();
    const cases = [_]Golden128{
        .{ .want = .{ 0x6c, 0x62, 0x27, 0x2e, 0x07, 0xbb, 0x01, 0x42, 0x62, 0xb8, 0x21, 0x75, 0x62, 0x95, 0xc5, 0x8d }, .in = "", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x05, 0x6c, 0x62, 0x27, 0x2e, 0x07, 0xbb, 0x01, 0x42, 0x62, 0xb8, 0x21, 0x75, 0x62, 0x95, 0xc5, 0x8d } },
        .{ .want = .{ 0xd2, 0x28, 0xcb, 0x69, 0x10, 0x1a, 0x8c, 0xaf, 0x78, 0x91, 0x2b, 0x70, 0x4e, 0x4a, 0x14, 0x1e }, .in = "a", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x05, 0x6c, 0x62, 0x27, 0x2e, 0x07, 0xbb, 0x01, 0x42, 0x62, 0xb8, 0x21, 0x75, 0x62, 0x95, 0xc5, 0x8d } },
        .{ .want = .{ 0x08, 0x80, 0x94, 0x5a, 0xee, 0xab, 0x1b, 0xe9, 0x5a, 0xa0, 0x73, 0x30, 0x55, 0x26, 0xc0, 0x88 }, .in = "ab", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x05, 0xd2, 0x28, 0xcb, 0x69, 0x10, 0x1a, 0x8c, 0xaf, 0x78, 0x91, 0x2b, 0x70, 0x4e, 0x4a, 0x14, 0x1e } },
        .{ .want = .{ 0xa6, 0x8b, 0xb2, 0xa4, 0x34, 0x8b, 0x58, 0x22, 0x83, 0x6d, 0xbc, 0x78, 0xc6, 0xae, 0xe7, 0x3b }, .in = "abc", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x05, 0xd2, 0x28, 0xcb, 0x69, 0x10, 0x1a, 0x8c, 0xaf, 0x78, 0x91, 0x2b, 0x70, 0x4e, 0x4a, 0x14, 0x1e } },
    };
    try testGolden128(&h, &cases);
}

test "fnv golden 128a" {
    var h = Fnv128a.new();
    const cases = [_]Golden128{
        .{ .want = .{ 0x6c, 0x62, 0x27, 0x2e, 0x07, 0xbb, 0x01, 0x42, 0x62, 0xb8, 0x21, 0x75, 0x62, 0x95, 0xc5, 0x8d }, .in = "", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x06, 0x6c, 0x62, 0x27, 0x2e, 0x07, 0xbb, 0x01, 0x42, 0x62, 0xb8, 0x21, 0x75, 0x62, 0x95, 0xc5, 0x8d } },
        .{ .want = .{ 0xd2, 0x28, 0xcb, 0x69, 0x6f, 0x1a, 0x8c, 0xaf, 0x78, 0x91, 0x2b, 0x70, 0x4e, 0x4a, 0x89, 0x64 }, .in = "a", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x06, 0x6c, 0x62, 0x27, 0x2e, 0x07, 0xbb, 0x01, 0x42, 0x62, 0xb8, 0x21, 0x75, 0x62, 0x95, 0xc5, 0x8d } },
        .{ .want = .{ 0x08, 0x80, 0x95, 0x44, 0xbb, 0xab, 0x1b, 0xe9, 0x5a, 0xa0, 0x73, 0x30, 0x55, 0xb6, 0x9a, 0x62 }, .in = "ab", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x06, 0xd2, 0x28, 0xcb, 0x69, 0x6f, 0x1a, 0x8c, 0xaf, 0x78, 0x91, 0x2b, 0x70, 0x4e, 0x4a, 0x89, 0x64 } },
        .{ .want = .{ 0xa6, 0x8d, 0x62, 0x2c, 0xec, 0x8b, 0x58, 0x22, 0x83, 0x6d, 0xbc, 0x79, 0x77, 0xaf, 0x7f, 0x3b }, .in = "abc", .half_marshal = .{ 0x66, 0x6e, 0x76, 0x06, 0xd2, 0x28, 0xcb, 0x69, 0x6f, 0x1a, 0x8c, 0xaf, 0x78, 0x91, 0x2b, 0x70, 0x4e, 0x4a, 0x89, 0x64 } },
    };
    try testGolden128a(&h, &cases);
}

test "fnv integrity" {
    const data = [_]u8{ '1', '2', 3, 4, 5 };

    var h32 = Fnv32.new();
    h32.write(&data);
    const s32 = try h32.sum(testing.allocator, &.{});
    defer testing.allocator.free(s32);
    try testing.expectEqual(Fnv32.size, s32.len);

    const s32_dup = try h32.sum(testing.allocator, &.{});
    defer testing.allocator.free(s32_dup);
    try testing.expectEqualSlices(u8, s32, s32_dup);

    try testing.expectEqual(std.mem.readInt(u32, s32[0..4], .big), h32.hash32().sum32());

    h32.reset();
    h32.write(&data);
    const s32_reset = try h32.sum(testing.allocator, &.{});
    defer testing.allocator.free(s32_reset);
    try testing.expectEqualSlices(u8, s32, s32_reset);

    h32.reset();
    h32.write(data[0..2]);
    h32.write(data[2..]);
    const s32_split = try h32.sum(testing.allocator, &.{});
    defer testing.allocator.free(s32_split);
    try testing.expectEqualSlices(u8, s32, s32_split);

    var h64 = Fnv64.new();
    h64.write(&data);
    const s64 = try h64.sum(testing.allocator, &.{});
    defer testing.allocator.free(s64);
    try testing.expectEqual(std.mem.readInt(u64, s64[0..8], .big), h64.hash64().sum64());
}

test "fnv writer" {
    const data = [_]u8{ 'h', 'i' };
    var h = Fnv64.new();
    const w = h.writer();
    try w.writeAll(&data);
    try w.flush();

    const direct = blk: {
        var g = Fnv64.new();
        g.write(&data);
        break :blk try g.sum(testing.allocator, &.{});
    };
    defer testing.allocator.free(direct);

    const via_writer = try h.sum(testing.allocator, &.{});
    defer testing.allocator.free(via_writer);
    try testing.expectEqualSlices(u8, direct, via_writer);
}
