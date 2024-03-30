const std = @import("std");

comptime {
    std.testing.refAllDecls(@import("./abstract-syntax.zig"));
    std.testing.refAllDecls(@import("./binary-parser.zig"));
}

pub const assert = @import("assert.zig");
