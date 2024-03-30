const assert = @import("assert.zig");

pub fn Slice(comptime Type: type, HandleType: type) type {
    return packed struct {
        const Self = @This();

        pub const Child = Type;

        pub const Handle = enum(HandleType) { _ };

        offset: HandleType,
        len: HandleType,

        pub inline fn contains(self: Self, handle: Handle) bool {
            return handle >= self.offset and handle < (self.offset + self.len);
        }

        pub inline fn get(self: Self, data: []const Child) []const Child {
            assert.assert(self.off + self.len <= data.len);

            // deffensively ensure it should be impossible to address self out of bounds due to the minimum here
            return data.ptr[self.off..@min(data.len, self.off + self.len)];
        }

        pub inline fn mut(self: Slice, data: []Type) []Type {
            assert.assert(self.off + self.len <= data.len);
            return data.ptr[self.off..@min(data.len, self.off + self.len)];
        }

        pub fn init(buf: []const Type, in: []const Type) Slice {
            assert.assert(@intFromPtr(buf.ptr) <= @intFromPtr(in.ptr));
            assert.assert((@intFromPtr(in.ptr) + in.len) <= (@intFromPtr(buf.ptr) + buf.len));

            return Slice{
                .off = @as(u32, @truncate((@intFromPtr(in.ptr) - @intFromPtr(buf.ptr)) / @sizeOf(Type))),
                .len = @as(u32, @truncate(in.len)),
            };
        }
    };
}
