const std = @import("std");

pub fn test_with_allocator(comptime test_fn: anytype, extra_args: anytype) !void {
    const allocator = std.testing.allocator;
    if (@import("test_options").check_allocation_failures) {
        try std.testing.checkAllAllocationFailures(allocator, test_fn, extra_args);
    } else {
        // This coe is simply taken from checkAllAllocationFailures
        switch (@typeInfo(@typeInfo(@TypeOf(test_fn)).Fn.return_type.?)) {
            .ErrorUnion => |info| {
                if (info.payload != void) {
                    @compileError("Return type must be !void");
                }
            },
            else => @compileError("Return type must be !void"),
        }
        if (@typeInfo(@TypeOf(extra_args)) != .Struct) {
            @compileError("Expected tuple or struct argument, found " ++ @typeName(@TypeOf(extra_args)));
        }

        const ArgsTuple = std.meta.ArgsTuple(@TypeOf(test_fn));
        const fn_args_fields = @typeInfo(ArgsTuple).Struct.fields;
        if (fn_args_fields.len == 0 or fn_args_fields[0].type != std.mem.Allocator) {
            @compileError("The provided function must have an " ++ @typeName(std.mem.Allocator) ++ " as its first argument");
        }
        const expected_args_tuple_len = fn_args_fields.len - 1;
        if (extra_args.len != expected_args_tuple_len) {
            @compileError("The provided function expects " ++ std.fmt.comptimePrint("{d}", .{expected_args_tuple_len}) ++ " extra arguments, but the provided tuple contains " ++ std.fmt.comptimePrint("{d}", .{extra_args.len}));
        }

        // Setup the tuple that will actually be used with @call (we'll need to insert
        // the failing allocator in field @"0" before each @call)
        var args: ArgsTuple = undefined;
        inline for (@typeInfo(@TypeOf(extra_args)).Struct.fields, 0..) |field, i| {
            const arg_i_str = comptime str: {
                var str_buf: [100]u8 = undefined;
                const args_i = i + 1;
                const str_len = std.fmt.formatIntBuf(&str_buf, args_i, 10, .lower, .{});
                break :str str_buf[0..str_len];
            };
            @field(args, arg_i_str) = @field(extra_args, field.name);
        }

        args.@"0" = allocator;

        try @call(.auto, test_fn, args);
    }
}
