pub inline fn assert(val: bool) void {
    if (!val) {
        fail("Assertion Failure");
    }
}

pub inline fn assert_named(val: bool, comptime message: []const u8, message_args: anytype) void {
    if (!val) {
        fail(comptime ("Assertion Failure: " ++ message), message_args);
    }
}

pub inline fn fail(comptime format: []const u8, args: anytype) noreturn {
    @setCold(true);

    @import("std").debug.panic(format, args);
}

pub inline fn ensure_size(comptime Type: type, size: usize) void {
    comptime {
        if (@sizeOf(Type) != size) {
            @compileLog("Type", @typeName(Type), "has size", @sizeOf(Type), "but should be", size);
            @compileError("Invalid Type Size");
        }
    }
}
