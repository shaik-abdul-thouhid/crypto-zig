//! Type-erased interfaces for incremental non-cryptographic hashers.
//!
//! These structs are **not** a single algorithm: they bundle a concrete hasher pointer (`data`)
//! with function pointers (`sumFn`, `resetFn`, …) so generic code can call `sum`, `reset`, and
//! `writer` without knowing the underlying type (e.g. `crc64.Digest`, `fnv.Fnv64`).
//!
//! Concrete types in this package expose `.hash()`, `.hash32()`, or `.hash64()` to build one of
//! these facades. **Thread safety:** the underlying hasher must not be shared across threads
//! without external synchronization, matching `std.hash` / `std.Io` usage.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

/// Variable-width digest: `size()` gives byte length; `sum` appends digest bytes after optional `prefix`.
///
/// For 32-bit-only or 64-bit-only facades, prefer `Hash32` or `Hash64` to get `sum32` / `sum64`.
pub const Hash = struct {
    /// Opaque pointer to the concrete hasher (e.g. `*Fnv128`). Do not reinterpret unless you know the type.
    data: *anyopaque,
    sumFn: *const fn (*anyopaque, Allocator, []const u8) anyerror![]u8,
    resetFn: *const fn (*anyopaque) void,
    sizeFn: *const fn (*anyopaque) usize,
    blockSizeFn: *const fn (*anyopaque) usize,
    writerFn: *const fn (*anyopaque) *Writer,

    /// Returns a new buffer `prefix ++ digest`. Allocates with `allocator`; caller must free the slice.
    /// Does not mutate hasher state. Fails only on allocation failure.
    pub fn sum(self: *const Hash, allocator: Allocator, data: []const u8) anyerror![]u8 {
        return self.sumFn(self.data, allocator, data);
    }

    /// Clears accumulated input; digest returns to the initial value for the current seed/table.
    pub fn reset(self: *const Hash) void {
        self.resetFn(self.data);
    }

    /// Digest length in bytes (e.g. 4 for Adler-32, 8 for CRC-64).
    pub fn size(self: *const Hash) usize {
        return self.sizeFn(self.data);
    }

    /// Hint for optimal chunk size; hashing still accepts any write length. Same role as Go `hash.Hash.BlockSize`.
    pub fn blockSize(self: *const Hash) usize {
        return self.blockSizeFn(self.data);
    }

    /// Streaming writes. If the implementation uses an internal buffer, **`flush` the writer** before `sum`.
    pub fn writer(self: *const Hash) *Writer {
        return self.writerFn(self.data);
    }
};

/// Like `Hash` but includes a native `u32` digest for 32-bit algorithms (CRC-32, FNV-32, …).
pub const Hash32 = struct {
    data: *anyopaque,
    sumFn: *const fn (*anyopaque, Allocator, []const u8) anyerror![]u8,
    resetFn: *const fn (*anyopaque) void,
    sizeFn: *const fn (*anyopaque) usize,
    blockSizeFn: *const fn (*anyopaque) usize,
    sum32Fn: *const fn (*anyopaque) u32,
    writerFn: *const fn (*anyopaque) *Writer,

    /// Allocated digest bytes (big-endian where the algorithm defines a byte order). Caller frees.
    pub fn sum(self: *const Hash32, allocator: Allocator, data: []const u8) anyerror![]u8 {
        return self.sumFn(self.data, allocator, data);
    }

    pub fn reset(self: *const Hash32) void {
        self.resetFn(self.data);
    }

    pub fn size(self: *const Hash32) usize {
        return self.sizeFn(self.data);
    }

    pub fn blockSize(self: *const Hash32) usize {
        return self.blockSizeFn(self.data);
    }

    /// Current digest as a `u32` (same value as the last four bytes of `sum` in big-endian form for typical algorithms).
    pub fn sum32(self: *const Hash32) u32 {
        return self.sum32Fn(self.data);
    }

    pub fn writer(self: *const Hash32) *Writer {
        return self.writerFn(self.data);
    }
};

/// Like `Hash` but includes a native `u64` digest for 64-bit algorithms (CRC-64, FNV-64, …).
pub const Hash64 = struct {
    data: *anyopaque,
    sumFn: *const fn (*anyopaque, Allocator, []const u8) anyerror![]u8,
    resetFn: *const fn (*anyopaque) void,
    sizeFn: *const fn (*anyopaque) usize,
    blockSizeFn: *const fn (*anyopaque) usize,
    sum64Fn: *const fn (*anyopaque) u64,
    writerFn: *const fn (*anyopaque) *Writer,

    /// Allocated digest bytes. Caller frees.
    pub fn sum(self: *const Hash64, allocator: Allocator, data: []const u8) anyerror![]u8 {
        return self.sumFn(self.data, allocator, data);
    }

    pub fn reset(self: *const Hash64) void {
        self.resetFn(self.data);
    }

    pub fn size(self: *const Hash64) usize {
        return self.sizeFn(self.data);
    }

    pub fn blockSize(self: *const Hash64) usize {
        return self.blockSizeFn(self.data);
    }

    /// Current digest as a `u64` (matches big-endian `sum` layout where applicable).
    pub fn sum64(self: *const Hash64) u64 {
        return self.sum64Fn(self.data);
    }

    pub fn writer(self: *const Hash64) *Writer {
        return self.writerFn(self.data);
    }
};

/// Extends the `Hash` surface with **`clone`**: duplicate hasher state (Go `hash.Cloner` pattern).
///
/// **`clone` returns `*anyopaque`:** the implementation decides the concrete type; the caller is
/// responsible for knowing how to free or reuse it. No concrete hasher in this package currently
/// wires `Cloner`; it is reserved for APIs that implement `cloneFn`.
pub const Cloner = struct {
    data: *anyopaque,
    sumFn: *const fn (*anyopaque, Allocator, []const u8) anyerror![]u8,
    resetFn: *const fn (*anyopaque) void,
    sizeFn: *const fn (*anyopaque) usize,
    blockSizeFn: *const fn (*anyopaque) usize,
    cloneFn: *const fn (*anyopaque) *anyopaque,
    writerFn: *const fn (*anyopaque) *Writer,

    pub fn sum(self: *const Cloner, allocator: Allocator, data: []const u8) anyerror![]u8 {
        return self.sumFn(self.data, allocator, data);
    }

    pub fn reset(self: *const Cloner) void {
        self.resetFn(self.data);
    }

    pub fn size(self: *const Cloner) usize {
        return self.sizeFn(self.data);
    }

    pub fn blockSize(self: *const Cloner) usize {
        return self.blockSizeFn(self.data);
    }

    /// Opaque duplicate of the hasher; lifetime/allocator are implementation-defined.
    pub fn clone(self: *const Cloner) *anyopaque {
        return self.cloneFn(self.data);
    }

    pub fn writer(self: *const Cloner) *Writer {
        return self.writerFn(self.data);
    }
};
