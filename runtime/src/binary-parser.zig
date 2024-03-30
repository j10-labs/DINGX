//
// THIS FILE IMPLEMENTS THE WASM SPEC CHAPTER 5 VERSION 2.0 (DRAFT 2023-06-14).
//

const abstract_syntax = @import("abstract-syntax.zig");
const std = @import("std");
const assert = @import("assert.zig");
const Allocator = std.mem.Allocator;
const test_with_allocator = @import("testing-util.zig").test_with_allocator;

inline fn read_file_header(reader: anytype) !void {
    if (try read_byte(reader) != 0x00) return ParserError.InvalidHeader;
    if (try read_byte(reader) != 0x61) return ParserError.InvalidHeader;
    if (try read_byte(reader) != 0x73) return ParserError.InvalidHeader;
    if (try read_byte(reader) != 0x6D) return ParserError.InvalidHeader;
    if (try read_byte(reader) != 0x01) return ParserError.InvalidHeader;
    if (try read_byte(reader) != 0x00) return ParserError.InvalidHeader;
    if (try read_byte(reader) != 0x00) return ParserError.InvalidHeader;
    if (try read_byte(reader) != 0x00) return ParserError.InvalidHeader;
}

pub fn parse(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) !abstract_syntax.Module {
    try read_file_header(reader);
    return try read_module(allocator, buffers, reader);
}

pub inline fn comptime_parse(allocator: Allocator, buffers: abstract_syntax.Buffers, reader: anytype) !abstract_syntax.Module {
    comptime try read_file_header(reader);
    return try read_module(allocator, buffers, reader);
}

test "Parse Empty Module" {
    try test_with_allocator(struct {
        fn f(input_allocator: Allocator) !void {
            var allocator = std.heap.ArenaAllocator.init(input_allocator);
            defer allocator.deinit();
            const buffer: []const u8 = &.{ 0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00 };
            var stream = std.io.fixedBufferStream(buffer);
            const reader = stream.reader();
            var instructions = @as([4096]abstract_syntax.Instruction, undefined);
            var buffers: abstract_syntax.Buffers = .{
                .instructions = &instructions,
                .instructions_next = 0,
            };
            const module = try parse(allocator.allocator(), &buffers, reader);
            _ = module;
        }
    }.f, .{});
}

/// See WASM Spec 5.3.1
fn read_number_type(reader: anytype) !abstract_syntax.NumType {
    return switch (try read_byte(reader)) {
        0x7F => .I32,
        0x7E => .I64,
        0x7D => .F32,
        0x7C => .F64,
        else => return ParserError.InvalidEnumValue,
    };
}

test "Reader Number Type" {
    const buffer: []const u8 = &.{0x7E};
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_number_type(&reader);
    const expected: abstract_syntax.NumType = .I64;
    try std.testing.expectEqual(expected, result);
}

/// See WASM Spec 5.3.2
fn read_vector_type(reader: anytype) !abstract_syntax.VecType {
    return switch (try read_byte(reader)) {
        0x7B => .V128,
        else => return ParserError.InvalidEnumValue,
    };
}

test "Reader Vec Type" {
    const buffer: []const u8 = &.{0x7B};
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_vector_type(&reader);
    const expected: abstract_syntax.VecType = .V128;
    try std.testing.expectEqual(expected, result);
}

/// See WASM Spec 5.3.3
fn read_ref_type(reader: anytype) !abstract_syntax.RefType {
    return switch (try read_byte(reader)) {
        0x70 => undefined, // funcref
        0x6F => undefined, // externref
        else => return ParserError.InvalidEnumValue,
    };
}

test "Reader Ref Type" {
    const buffer: []const u8 = &.{0x70};
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_ref_type(&reader);
    const expected: abstract_syntax.RefType = undefined;
    try std.testing.expectEqual(expected, result);
}

/// See WASM Spec 5.3.4
fn read_value_type(reader: anytype) !abstract_syntax.ValueType {
    return parse_value_type(try read_byte(reader));
}

/// See WASM Spec 5.3.4
fn parse_value_type(byte: u8) !abstract_syntax.ValueType {
    return switch (byte) {
        0x70 => .{ .Ref = undefined }, // funcref
        0x6F => .{ .Ref = undefined }, // externref
        0x7B => .{ .Vec = .V128 },
        0x7C => .{ .Num = .F64 },
        0x7D => .{ .Num = .F32 },
        0x7E => .{ .Num = .I64 },
        0x7F => .{ .Num = .I32 },
        else => return ParserError.InvalidEnumValue,
    };
}

test "Reader Value Type" {
    const buffer: []const u8 = &.{0x7B};
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_value_type(&reader);
    const expected: abstract_syntax.ValueType = .{ .Vec = .V128 };
    try std.testing.expectEqual(expected, result);
}

/// See WASM Spec 5.3.5
fn read_result_type(allocator: Allocator, reader: anytype) !abstract_syntax.ResultType {
    return read_vector(abstract_syntax.ValueType, allocator, reader, read_value_type);
}

test "Read Result Type" {
    try test_with_allocator(struct {
        fn f(input_allocator: Allocator) !void {
            var allocator = input_allocator;
            const buffer: []const u8 = &.{ 0x03, 0x7B, 0x7C, 0x7F };
            var stream = std.io.fixedBufferStream(buffer);
            var reader = stream.reader();
            const result = try read_result_type(allocator, &reader);
            defer allocator.free(result);
            const expected: abstract_syntax.ResultType = &.{ .{ .Vec = .V128 }, .{ .Num = .F64 }, .{ .Num = .I32 } };
            try std.testing.expectEqualSlices(abstract_syntax.ValueType, expected, result);
        }
    }.f, .{});
}

/// See WASM Spec 5.3.6
fn read_function_type(allocator: Allocator, reader: anytype) !abstract_syntax.FuncType {
    switch (try read_byte(reader)) {
        0x60 => {
            const args = try read_result_type(allocator, reader);
            errdefer allocator.free(args);
            const result = try read_result_type(allocator, reader);
            errdefer allocator.free(result);
            return .{
                .args = args,
                .result = result,
            };
        },
        else => return ParserError.InvalidEnumValue,
    }
}

test "Read Function Type" {
    try test_with_allocator(struct {
        fn f(input_allocator: Allocator) !void {
            var allocator = input_allocator;
            const buffer: []const u8 = &.{ 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F };
            var stream = std.io.fixedBufferStream(buffer);
            var reader = stream.reader();
            const result = try read_function_type(allocator, &reader);
            defer allocator.free(result.args);
            defer allocator.free(result.result);
            const expected: abstract_syntax.FuncType = .{ .args = &.{
                .{ .Num = .I32 },
                .{ .Num = .I32 },
            }, .result = &.{.{ .Num = .I32 }} };
            try std.testing.expectEqualDeep(expected, result);
        }
    }.f, .{});
}

/// See WASM Spec 5.3.7
fn read_limits(reader: anytype) !abstract_syntax.Limits {
    switch (try read_byte(reader)) {
        0x00 => {
            return .{ .max = null, .min = try read_u32(reader) };
        },
        0x01 => {
            return .{ .min = try read_u32(reader), .max = try read_u32(reader) };
        },
        else => return ParserError.InvalidEnumValue,
    }
}

test "Read Limit" {
    const buffer: []const u8 = &.{ 0x00, 0x01 };
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_limits(&reader);
    const expected: abstract_syntax.Limits = .{ .max = null, .min = 0x01 };
    try std.testing.expectEqual(expected, result);
}

/// See WASM Spec 5.3.8
fn read_memory_type(reader: anytype) !abstract_syntax.MemoryType {
    return .{ .limits = try read_limits(reader) };
}

test "Read Memory Type" {
    const buffer: []const u8 = &.{ 0x01, 0x01, 0x02 };
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_memory_type(&reader);
    const expected: abstract_syntax.MemoryType = .{ .limits = .{ .max = 0x02, .min = 0x01 } };
    try std.testing.expectEqual(expected, result);
}

/// See WASM Spec 5.3.9
fn read_table_type(reader: anytype) !abstract_syntax.TableType {
    const reftype = try read_ref_type(reader);
    const limits = try read_limits(reader);
    return .{ .limits = limits, .reftype = reftype };
}

test "Read Table Type" {
    const buffer: []const u8 = &.{ 0x70, 0x01, 0x01, 0x02 };
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_table_type(&reader);
    const expected: abstract_syntax.TableType = .{ .limits = .{ .max = 0x02, .min = 0x01 }, .reftype = undefined };
    try std.testing.expectEqual(expected, result);
}

/// See WASM Spec 5.3.10
fn read_mutability(reader: anytype) !abstract_syntax.Mutability {
    return switch (try read_byte(reader)) {
        0x00 => .@"const",
        0x01 => .@"var",
        else => return ParserError.InvalidEnumValue,
    };
}

/// See WASM Spec 5.3.10
fn read_global_type(reader: anytype) !abstract_syntax.GlobalType {
    const t = try read_value_type(reader);
    const m = try read_mutability(reader);
    return .{ .mutability = m, .valueType = t };
}

test "Read Global Type" {
    const buffer: []const u8 = &.{ 0x7F, 0x00 };
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_global_type(&reader);
    const expected: abstract_syntax.GlobalType = .{ .valueType = .{ .Num = .I32 }, .mutability = .@"const" };
    try std.testing.expectEqual(expected, result);
}

/// See WASM Spec 5.4.1
fn read_block_type(reader: anytype) !abstract_syntax.BlockType {
    const b = try read_byte(reader);
    var peeked = peekedReader(reader, b);
    const peeked_reader = peeked.reader();
    return switch (b) {
        0x40 => .{ .Inline = null },
        0x6F...0x7F => .{ .Inline = try read_value_type(peeked_reader) },
        else => .{ .TypeIndex = switch (try std.leb.readILEB128(i33, peeked_reader)) {
            0...std.math.maxInt(u32) => |idx| @as(u32, @intCast(idx)),
            else => return ParserError.LEBTooLong,
        } },
    };
}

test "Read Block Type Inline Empty" {
    const buffer: []const u8 = &.{0x40};
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_block_type(&reader);
    const expected: abstract_syntax.BlockType = .{ .Inline = null };
    try std.testing.expectEqual(expected, result);
}

test "Read Block Type Inline" {
    const buffer: []const u8 = &.{0x7C};
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_block_type(&reader);
    const expected: abstract_syntax.BlockType = .{ .Inline = .{ .Num = .F64 } };
    try std.testing.expectEqual(expected, result);
}

test "Read Block Type Type Idx" {
    const buffer: []const u8 = &.{0x03};
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_block_type(&reader);
    const expected: abstract_syntax.BlockType = .{ .TypeIndex = 0x03 };
    try std.testing.expectEqual(expected, result);
}

const InstructionResult = struct {
    instr: abstract_syntax.InstructionHandle,
    was_else: bool,
};

fn read_expr(buffers: *abstract_syntax.Buffers, allocator: Allocator, reader: anytype) !InstructionResult {
    var first: abstract_syntax.InstructionHandle = abstract_syntax.InstructionHandle.INVALID;
    var prev: abstract_syntax.InstructionHandle = abstract_syntax.InstructionHandle.INVALID;
    while (true) {
        const opres = try read_opcode(buffers, allocator, reader);
        const op = switch (opres) {
            .End => break,
            .RealOpCode => |op| op,
            .Else => {
                if (first == abstract_syntax.InstructionHandle.INVALID) {
                    assert.fail("Else cannot be encountered without existing instruction", .{});
                }
                return .{ .instr = first, .was_else = true };
            },
        };
        const instruction = try buffers.allocate_instruction();
        if (buffers.resolve_instruction_mut(prev)) |n| {
            n.*.next = instruction;
        }
        if (first == abstract_syntax.InstructionHandle.INVALID) {
            first = instruction;
        }

        buffers.resolve_instruction_mut(instruction).?.* = .{
            .op_code = op,
            .next = abstract_syntax.InstructionHandle.INVALID,
            .prev = prev,
        };
        prev = instruction;
    }
    if (first == abstract_syntax.InstructionHandle.INVALID) {
        assert.fail("Cannot read expr but no instruction was read?!", .{});
    }
    return .{ .instr = first, .was_else = false };
}

fn read_standard_instruction(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) !abstract_syntax.InstructionHandle {
    const result = try read_expr(buffers, allocator, reader);
    if (result.was_else) {
        return ParserError.NonStandardInstruction;
    }
    return result.instr;
}

test "Read 3 Instructions" {
    try test_with_allocator(struct {
        fn f(input_allocator: Allocator) !void {
            const allocator = input_allocator;
            const buffer: []const u8 = &.{ 0x00, 0x00, 0x00, 0x0B };
            var stream = std.io.fixedBufferStream(buffer);
            var reader = stream.reader();
            var instructions = @as([4096]abstract_syntax.Instruction, undefined);
            var buffers: abstract_syntax.Buffers = .{
                .instructions = &instructions,
                .instructions_next = 0,
            };
            const handle: abstract_syntax.InstructionHandle = try read_standard_instruction(allocator, &buffers, &reader);
            var node = buffers.resolve_instruction(handle).?;
            try std.testing.expectEqual(@as(abstract_syntax.OpCode, .Unreachable), node.*.op_code);
            node = buffers.resolve_instruction(node.*.next) orelse unreachable;
            try std.testing.expectEqual(@as(abstract_syntax.OpCode, .Unreachable), node.*.op_code);
            node = buffers.resolve_instruction(node.*.next) orelse unreachable;
            try std.testing.expectEqual(@as(abstract_syntax.OpCode, .Unreachable), node.*.op_code);
            try std.testing.expectEqual(abstract_syntax.InstructionHandle.INVALID, node.*.next);
        }
    }.f, .{});
}

test "Read Instructions with Block" {
    try test_with_allocator(struct {
        fn f(input_allocator: Allocator) !void {
            const allocator = input_allocator;
            const buffer: []const u8 = &.{ 0x00, 0x02, 0x40, 0x00, 0x00, 0x0B, 0x0B };
            var stream = std.io.fixedBufferStream(buffer);
            var reader = stream.reader();
            var instructions = @as([4096]abstract_syntax.Instruction, undefined);
            var buffers: abstract_syntax.Buffers = .{
                .instructions = &instructions,
                .instructions_next = 0,
            };
            const handle: abstract_syntax.InstructionHandle = try read_standard_instruction(allocator, &buffers, &reader);
            var node = buffers.resolve_instruction(handle).?;
            try std.testing.expectEqual(@as(abstract_syntax.OpCode, .Unreachable), node.*.op_code);
            node = buffers.resolve_instruction(node.*.next) orelse unreachable;
            switch (node.*.op_code) {
                .Block => |b| {
                    try std.testing.expectEqual(@as(abstract_syntax.BlockType, .{ .Inline = null }), b.blocktype);
                    var node2: *const abstract_syntax.Instruction = buffers.resolve_instruction(b.body) orelse unreachable;

                    try std.testing.expectEqual(@as(abstract_syntax.OpCode, .Unreachable), node2.*.op_code);
                    node2 = buffers.resolve_instruction(node2.*.next) orelse unreachable;
                    try std.testing.expectEqual(@as(abstract_syntax.OpCode, .Unreachable), node2.*.op_code);
                    try std.testing.expectEqual(abstract_syntax.InstructionHandle.INVALID, node2.*.next);
                },
                else => unreachable,
            }
            try std.testing.expectEqual(abstract_syntax.InstructionHandle.INVALID, node.*.next);
        }
    }.f, .{});
}

test "Read If/Else Block" {
    try test_with_allocator(struct {
        fn f(input_allocator: Allocator) !void {
            const allocator = input_allocator;
            const buffer: []const u8 = &.{ 0x04, 0x40, 0x00, 0x05, 0x01, 0x0B, 0x01, 0x0B };
            var stream = std.io.fixedBufferStream(buffer);
            var reader = stream.reader();
            var instructions = @as([4096]abstract_syntax.Instruction, undefined);
            var buffers: abstract_syntax.Buffers = .{
                .instructions = &instructions,
                .instructions_next = 0,
            };
            const handle: abstract_syntax.InstructionHandle = try read_standard_instruction(allocator, &buffers, &reader);
            var node = buffers.resolve_instruction(handle).?;
            switch (node.*.op_code) {
                .IfElse => |b| {
                    try std.testing.expectEqual(@as(abstract_syntax.BlockType, .{ .Inline = null }), b.blocktype);
                    const node2: *const abstract_syntax.Instruction = buffers.resolve_instruction(b.body) orelse unreachable;

                    try std.testing.expectEqual(@as(abstract_syntax.OpCode, .Unreachable), node2.*.op_code);
                    try std.testing.expectEqual(abstract_syntax.InstructionHandle.INVALID, node2.*.next);

                    const node3: *const abstract_syntax.Instruction = buffers.resolve_instruction(b.elseBody) orelse unreachable;

                    try std.testing.expectEqual(@as(abstract_syntax.OpCode, .Nop), node3.*.op_code);
                    try std.testing.expectEqual(abstract_syntax.InstructionHandle.INVALID, node3.*.next);
                },
                else => unreachable,
            }
            node = buffers.resolve_instruction(node.*.next) orelse unreachable;
            try std.testing.expectEqual(@as(abstract_syntax.OpCode, .Nop), node.*.op_code);
            try std.testing.expectEqual(abstract_syntax.InstructionHandle.INVALID, node.*.next);
        }
    }.f, .{});
}

fn instruction_linked_list_to_ops(allocator: Allocator, buffers: *abstract_syntax.Buffers, head: abstract_syntax.InstructionHandle) !std.ArrayList(abstract_syntax.OpCode) {
    if (!@import("builtin").is_test) {
        @compileError("instruction_linked_list_to_ops should only be used during testing!");
    }
    var list = std.ArrayList(abstract_syntax.OpCode).init(allocator);
    var node: abstract_syntax.InstructionHandle = head;
    while (abstract_syntax.resolve_instruction(node)) |n| {
        node = n.next;
        try list.append(n.op_code);
        buffers.free(n);
    }
    return list;
}

const OpCodeResult = union(enum) {
    End,
    Else,
    RealOpCode: abstract_syntax.OpCode,
};

/// See WASM Spec 5.4.1
fn read_opcode(buffers: *abstract_syntax.Buffers, allocator: Allocator, reader: anytype) anyerror!OpCodeResult {
    return switch (try read_byte(reader)) {
        0x0B => .End,
        0x05 => .Else,
        0x00 => .{ .RealOpCode = .Unreachable },
        0x01 => .{ .RealOpCode = .Nop },
        0x02 => .{ .RealOpCode = .{ .Block = .{ .blocktype = try read_block_type(reader), .body = try read_standard_instruction(allocator, buffers, reader) } } },
        0x03 => .{ .RealOpCode = .{ .Loop = .{ .blocktype = try read_block_type(reader), .body = try read_standard_instruction(allocator, buffers, reader) } } },
        0x04 => .{ .RealOpCode = try read_if_block(buffers, allocator, reader) },
        0x0C => .{ .RealOpCode = .{ .Branch = .{ .idx = try read_u32(reader) } } },
        0x0D => .{ .RealOpCode = .{ .BranchIf = .{ .idx = try read_u32(reader) } } },
        0x0E => .{ .RealOpCode = .{ .BranchTable = .{ .table = try read_vector(abstract_syntax.LabelIdx, allocator, reader, read_u32), .fallback = try read_u32(reader) } } },
        0x0F => .{ .RealOpCode = .Return },
        0x10 => .{ .RealOpCode = .{ .Call = .{ .idx = try read_u32(reader) } } },
        0x11 => .{ .RealOpCode = .{ .CallIndirect = .{ .type = try read_u32(reader), .table = try read_u32(reader) } } },

        0xD0 => .{ .RealOpCode = .{ .RefNull = .{ .type = try read_ref_type(reader) } } },
        0xD1 => .{ .RealOpCode = .RefIsNull },
        0xD2 => .{ .RealOpCode = .{ .RefFunc = .{ .idx = try read_u32(reader) } } },

        0x1A => .{ .RealOpCode = .Drop },
        0x1B => .{ .RealOpCode = .{ .Select = .{ .type = null } } },
        0x1C => .{ .RealOpCode = .{ .Select = .{ .type = try read_vector(abstract_syntax.ValueType, allocator, reader, read_value_type) } } },

        0x20 => .{ .RealOpCode = .{ .LocalGet = .{ .idx = try read_u32(reader) } } },
        0x21 => .{ .RealOpCode = .{ .LocalSet = .{ .idx = try read_u32(reader) } } },
        0x22 => .{ .RealOpCode = .{ .LocalTee = .{ .idx = try read_u32(reader) } } },
        0x23 => .{ .RealOpCode = .{ .GlobalGet = .{ .idx = try read_u32(reader) } } },
        0x24 => .{ .RealOpCode = .{ .GlobalSet = .{ .idx = try read_u32(reader) } } },

        0x25 => .{ .RealOpCode = .{ .TableGet = .{ .idx = try read_u32(reader) } } },
        0x26 => .{ .RealOpCode = .{ .TableSet = .{ .idx = try read_u32(reader) } } },

        0x28 => .{ .RealOpCode = .{ .I32Load = .{ .memArg = try read_memarg(reader) } } },
        0x29 => .{ .RealOpCode = .{ .I64Load = .{ .memArg = try read_memarg(reader) } } },
        0x2A => .{ .RealOpCode = .{ .F32Load = .{ .memArg = try read_memarg(reader) } } },
        0x2B => .{ .RealOpCode = .{ .F64Load = .{ .memArg = try read_memarg(reader) } } },
        0x2C => .{ .RealOpCode = .{ .I32Load8Signed = .{ .memArg = try read_memarg(reader) } } },
        0x2D => .{ .RealOpCode = .{ .I32Load8Unsigned = .{ .memArg = try read_memarg(reader) } } },
        0x2E => .{ .RealOpCode = .{ .I32Load16Signed = .{ .memArg = try read_memarg(reader) } } },
        0x2F => .{ .RealOpCode = .{ .I32Load16Unsigned = .{ .memArg = try read_memarg(reader) } } },
        0x30 => .{ .RealOpCode = .{ .I64Load8Signed = .{ .memArg = try read_memarg(reader) } } },
        0x31 => .{ .RealOpCode = .{ .I64Load8Unsigned = .{ .memArg = try read_memarg(reader) } } },
        0x32 => .{ .RealOpCode = .{ .I64Load16Signed = .{ .memArg = try read_memarg(reader) } } },
        0x33 => .{ .RealOpCode = .{ .I64Load16Unsigned = .{ .memArg = try read_memarg(reader) } } },
        0x34 => .{ .RealOpCode = .{ .I64Load32Signed = .{ .memArg = try read_memarg(reader) } } },
        0x35 => .{ .RealOpCode = .{ .I64Load32Unsigned = .{ .memArg = try read_memarg(reader) } } },
        0x36 => .{ .RealOpCode = .{ .I32Store = .{ .memArg = try read_memarg(reader) } } },
        0x37 => .{ .RealOpCode = .{ .I64Store = .{ .memArg = try read_memarg(reader) } } },
        0x38 => .{ .RealOpCode = .{ .F32Store = .{ .memArg = try read_memarg(reader) } } },
        0x39 => .{ .RealOpCode = .{ .F64Store = .{ .memArg = try read_memarg(reader) } } },
        0x3A => .{ .RealOpCode = .{ .I32Store8 = .{ .memArg = try read_memarg(reader) } } },
        0x3B => .{ .RealOpCode = .{ .I32Store16 = .{ .memArg = try read_memarg(reader) } } },
        0x3C => .{ .RealOpCode = .{ .I64Store8 = .{ .memArg = try read_memarg(reader) } } },
        0x3D => .{ .RealOpCode = .{ .I64Store16 = .{ .memArg = try read_memarg(reader) } } },
        0x3E => .{ .RealOpCode = .{ .I64Store32 = .{ .memArg = try read_memarg(reader) } } },
        0x3F => switch (try read_byte(reader)) {
            0x00 => .{ .RealOpCode = .MemorySize },
            else => ParserError.InvalidEnumValue,
        },
        0x40 => switch (try read_byte(reader)) {
            0x00 => .{ .RealOpCode = .MemoryGrow },
            else => ParserError.InvalidEnumValue,
        },
        0xFC => switch (try read_u32(reader)) {
            8 => memory_init: {
                const x = try read_u32(reader);
                break :memory_init switch (try read_byte(reader)) {
                    0x00 => .{ .RealOpCode = .{ .MemoryInit = .{ .idx = x } } },
                    else => ParserError.InvalidEnumValue,
                };
            },
            9 => .{ .RealOpCode = .{ .DataDrop = .{ .idx = try read_u32(reader) } } },
            10 => switch (try read_byte(reader)) {
                0x00 => switch (try read_byte(reader)) {
                    0x00 => .{ .RealOpCode = .MemoryCopy },
                    else => ParserError.InvalidEnumValue,
                },
                else => ParserError.InvalidEnumValue,
            },
            11 => switch (try read_byte(reader)) {
                0x00 => .{ .RealOpCode = .MemoryFill },
                else => ParserError.InvalidEnumValue,
            },

            0 => .{ .RealOpCode = .I32TruncateSaturateF32Signed },
            1 => .{ .RealOpCode = .I32TruncateSaturateF32Unsigned },
            2 => .{ .RealOpCode = .I32TruncateSaturateF64Signed },
            3 => .{ .RealOpCode = .I32TruncateSaturateF64Unsigned },
            4 => .{ .RealOpCode = .I64TruncateSaturateF32Signed },
            5 => .{ .RealOpCode = .I64TruncateSaturateF32Unsigned },
            6 => .{ .RealOpCode = .I64TruncateSaturateF64Signed },
            7 => .{ .RealOpCode = .I64TruncateSaturateF64Unsigned },

            12 => .{ .RealOpCode = .{ .TableInit = .{ .element = try read_u32(reader), .idx = try read_u32(reader) } } },
            13 => .{ .RealOpCode = .{ .ElementDrop = .{ .idx = try read_u32(reader) } } },
            14 => .{ .RealOpCode = .{ .TableCopy = .{ .dest = try read_u32(reader), .src = try read_u32(reader) } } },
            15 => .{ .RealOpCode = .{ .TableGrow = .{ .idx = try read_u32(reader) } } },
            16 => .{ .RealOpCode = .{ .TableSize = .{ .idx = try read_u32(reader) } } },
            17 => .{ .RealOpCode = .{ .TableFill = .{ .idx = try read_u32(reader) } } },

            // TODO: Vector Instructions

            else => ParserError.InvalidEnumValue,
        },

        0x41 => .{ .RealOpCode = .{ .I32Const = .{ .value = @bitCast(try std.leb.readILEB128(i32, reader)) } } },
        0x42 => .{ .RealOpCode = .{ .I64Const = .{ .value = @bitCast(try std.leb.readILEB128(i64, reader)) } } },
        0x43 => .{ .RealOpCode = .{ .F32Const = .{ .value = try read_f32(reader) } } },
        0x44 => .{ .RealOpCode = .{ .F64Const = .{ .value = try read_f64(reader) } } },

        0x45 => .{ .RealOpCode = .I32EqualZero },
        0x46 => .{ .RealOpCode = .I32Equal },
        0x47 => .{ .RealOpCode = .I32NotEqual },
        0x48 => .{ .RealOpCode = .I32LessThanSigned },
        0x49 => .{ .RealOpCode = .I32LessThanUnsigned },
        0x4A => .{ .RealOpCode = .I32GreaterThanSigned },
        0x4B => .{ .RealOpCode = .I32GreaterThanUnsigned },
        0x4C => .{ .RealOpCode = .I32LessThanOrEqualSigned },
        0x4D => .{ .RealOpCode = .I32LessThanOrEqualUnsigned },
        0x4E => .{ .RealOpCode = .I32GreaterThanOrEqualSigned },
        0x4F => .{ .RealOpCode = .I32GreaterThanOrEqualUnsigned },

        0x50 => .{ .RealOpCode = .I64EqualZero },
        0x51 => .{ .RealOpCode = .I64Equal },
        0x52 => .{ .RealOpCode = .I64NotEqual },
        0x53 => .{ .RealOpCode = .I64LessThanSigned },
        0x54 => .{ .RealOpCode = .I64LessThanUnsigned },
        0x55 => .{ .RealOpCode = .I64GreaterThanSigned },
        0x56 => .{ .RealOpCode = .I64GreaterThanUnsigned },
        0x57 => .{ .RealOpCode = .I64LessThanOrEqualSigned },
        0x58 => .{ .RealOpCode = .I64LessThanOrEqualUnsigned },
        0x59 => .{ .RealOpCode = .I64GreaterThanOrEqualSigned },
        0x5A => .{ .RealOpCode = .I64GreaterThanOrEqualUnsigned },

        0x5B => .{ .RealOpCode = .F32Equal },
        0x5C => .{ .RealOpCode = .F32NotEqual },
        0x5D => .{ .RealOpCode = .F32LessThan },
        0x5E => .{ .RealOpCode = .F32GreaterThan },
        0x5F => .{ .RealOpCode = .F32LessThanOrEqual },
        0x60 => .{ .RealOpCode = .F32GreaterThanOrEqual },

        0x61 => .{ .RealOpCode = .F64Equal },
        0x62 => .{ .RealOpCode = .F64NotEqual },
        0x63 => .{ .RealOpCode = .F64LessThan },
        0x64 => .{ .RealOpCode = .F64GreaterThan },
        0x65 => .{ .RealOpCode = .F64LessThanOrEqual },
        0x66 => .{ .RealOpCode = .F64GreaterThanOrEqual },

        0x67 => .{ .RealOpCode = .I32Clz },
        0x68 => .{ .RealOpCode = .I32Ctz },
        0x69 => .{ .RealOpCode = .I32PopCnt },
        0x6A => .{ .RealOpCode = .I32Add },
        0x6B => .{ .RealOpCode = .I32Sub },
        0x6C => .{ .RealOpCode = .I32Mul },
        0x6D => .{ .RealOpCode = .I32DivSigned },
        0x6E => .{ .RealOpCode = .I32DivUnsigned },
        0x6F => .{ .RealOpCode = .I32RemSigned },
        0x70 => .{ .RealOpCode = .I32RemUnsigned },
        0x71 => .{ .RealOpCode = .I32And },
        0x72 => .{ .RealOpCode = .I32Or },
        0x73 => .{ .RealOpCode = .I32Xor },
        0x74 => .{ .RealOpCode = .I32ShiftLeft },
        0x75 => .{ .RealOpCode = .I32ShiftRightSigned },
        0x76 => .{ .RealOpCode = .I32ShiftRightUnsigned },
        0x77 => .{ .RealOpCode = .I32RotateLeft },
        0x78 => .{ .RealOpCode = .I32RotateRight },

        0x79 => .{ .RealOpCode = .I64Clz },
        0x7A => .{ .RealOpCode = .I64Ctz },
        0x7B => .{ .RealOpCode = .I64PopCnt },
        0x7C => .{ .RealOpCode = .I64Add },
        0x7D => .{ .RealOpCode = .I64Sub },
        0x7E => .{ .RealOpCode = .I64Mul },
        0x7F => .{ .RealOpCode = .I64DivSigned },
        0x80 => .{ .RealOpCode = .I64DivUnsigned },
        0x81 => .{ .RealOpCode = .I64RemSigned },
        0x82 => .{ .RealOpCode = .I64RemUnsigned },
        0x83 => .{ .RealOpCode = .I64And },
        0x84 => .{ .RealOpCode = .I64Or },
        0x85 => .{ .RealOpCode = .I64Xor },
        0x86 => .{ .RealOpCode = .I64ShiftLeft },
        0x87 => .{ .RealOpCode = .I64ShiftRightSigned },
        0x88 => .{ .RealOpCode = .I64ShiftRightUnsigned },
        0x89 => .{ .RealOpCode = .I64RotateLeft },
        0x8A => .{ .RealOpCode = .I64RotateRight },

        0x8B => .{ .RealOpCode = .F32Abs },
        0x8C => .{ .RealOpCode = .F32Neg },
        0x8D => .{ .RealOpCode = .F32Ceil },
        0x8E => .{ .RealOpCode = .F32Floor },
        0x8F => .{ .RealOpCode = .F32Trunc },
        0x90 => .{ .RealOpCode = .F32Nearest },
        0x91 => .{ .RealOpCode = .F32Sqrt },
        0x92 => .{ .RealOpCode = .F32Add },
        0x93 => .{ .RealOpCode = .F32Sub },
        0x94 => .{ .RealOpCode = .F32Mul },
        0x95 => .{ .RealOpCode = .F32Div },
        0x96 => .{ .RealOpCode = .F32Min },
        0x97 => .{ .RealOpCode = .F32Max },
        0x98 => .{ .RealOpCode = .F32CopySign },

        0x99 => .{ .RealOpCode = .F64Abs },
        0x9A => .{ .RealOpCode = .F64Neg },
        0x9B => .{ .RealOpCode = .F64Ceil },
        0x9C => .{ .RealOpCode = .F64Floor },
        0x9D => .{ .RealOpCode = .F64Trunc },
        0x9E => .{ .RealOpCode = .F64Nearest },
        0x9F => .{ .RealOpCode = .F64Sqrt },
        0xA0 => .{ .RealOpCode = .F64Add },
        0xA1 => .{ .RealOpCode = .F64Sub },
        0xA2 => .{ .RealOpCode = .F64Mul },
        0xA3 => .{ .RealOpCode = .F64Div },
        0xA4 => .{ .RealOpCode = .F64Min },
        0xA5 => .{ .RealOpCode = .F64Max },
        0xA6 => .{ .RealOpCode = .F64CopySign },

        0xA7 => .{ .RealOpCode = .I32WrapI64 },
        0xA8 => .{ .RealOpCode = .I32TruncateF32Signed },
        0xA9 => .{ .RealOpCode = .I32TruncateF32Unsigned },
        0xAA => .{ .RealOpCode = .I32TruncateF64Signed },
        0xAB => .{ .RealOpCode = .I32TruncateF64Unsigned },
        0xAC => .{ .RealOpCode = .I64Extend32Signed },
        0xAD => .{ .RealOpCode = .I64Extend32Unsigned },
        0xAE => .{ .RealOpCode = .I64TruncateF32Signed },
        0xAF => .{ .RealOpCode = .I64TruncateF32Unsigned },
        0xB0 => .{ .RealOpCode = .I64TruncateF64Signed },
        0xB1 => .{ .RealOpCode = .I64TruncateF64Unsigned },
        0xB2 => .{ .RealOpCode = .F32ConvertI32Signed },
        0xB3 => .{ .RealOpCode = .F32ConvertI32Unsigned },
        0xB4 => .{ .RealOpCode = .F32ConvertI64Signed },
        0xB5 => .{ .RealOpCode = .F32ConvertI64Unsigned },
        0xB6 => .{ .RealOpCode = .F32DemoteF64 },
        0xB7 => .{ .RealOpCode = .F64ConvertI32Signed },
        0xB8 => .{ .RealOpCode = .F64ConvertI32Unsigned },
        0xB9 => .{ .RealOpCode = .F64ConvertI64Signed },
        0xBA => .{ .RealOpCode = .F64ConvertI64Unsigned },
        0xBB => .{ .RealOpCode = .F64PromoteF32 },
        0xBC => .{ .RealOpCode = .I32ReinterpretF32 },
        0xBD => .{ .RealOpCode = .I64ReinterpretF64 },
        0xBE => .{ .RealOpCode = .F32ReinterpretI32 },
        0xBF => .{ .RealOpCode = .F64ReinterpretI64 },

        0xC0 => .{ .RealOpCode = .I32Extend8Signed },
        0xC1 => .{ .RealOpCode = .I32Extend16Signed },
        0xC2 => .{ .RealOpCode = .I64Extend8Signed },
        0xC3 => .{ .RealOpCode = .I64Extend16Signed },
        0xC4 => .{ .RealOpCode = .I64Extend32Signed },

        else => ParserError.InvalidEnumValue,
    };
}

fn read_module(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) !abstract_syntax.Module {
    var module: abstract_syntax.Module = .{
        .types = &.{},
        .funcs = &.{},
        .tables = &.{},
        .memories = &.{},
        .globals = &.{},
        .elements = &.{},
        .datas = &.{},
        .start = null,
        .imports = &.{},
        .exports = &.{},
    };

    var funcs: ?[]abstract_syntax.Func = null;

    while (true) {
        const section_id = read_byte(reader) catch break;
        const size = try read_u32(reader);
        var limited_section_reader = std.io.limitedReader(reader, size);
        const section_reader = limited_section_reader.reader();

        switch (section_id) {
            0 => {
                const custom_section = try read_custom_section(allocator, section_reader);
                _ = custom_section;
            },
            1 => {
                const type_section = try read_type_section(allocator, reader);
                module.types = type_section;
            },
            2 => {
                const import_section = try read_import_section(allocator, reader);
                module.imports = import_section;
            },
            3 => {
                const function_section = try read_function_section(allocator, reader);

                if (funcs == null) {
                    funcs = try allocator.alloc(abstract_syntax.Func, function_section.len);
                }

                for (function_section, funcs.?) |type_idx, *func| {
                    func.*.type = type_idx;
                }
            },
            4 => {
                const table_section = try read_table_section(allocator, reader);
                module.tables = table_section;
            },
            5 => {
                const memory_section = try read_memory_section(allocator, reader);
                module.memories = memory_section;
            },
            6 => {
                const global_section = try read_global_section(allocator, buffers, reader);
                module.globals = global_section;
            },
            7 => {
                const export_section = try read_export_section(allocator, reader);
                module.exports = export_section;
            },
            8 => {
                const start_section = try read_start_section(reader);
                module.start = start_section;
            },
            9 => {
                const element_section = try read_element_section(allocator, buffers, reader);
                module.elements = element_section;
            },
            10 => {
                const code_section = try read_code_section(allocator, buffers, reader);

                if (funcs == null) {
                    funcs = try allocator.alloc(abstract_syntax.Func, code_section.len);
                }

                for (code_section, funcs.?) |code, *func| {
                    func.*.locals = code.locals;
                    func.*.body = code.body;
                }
            },
            11 => {
                const data_section = try read_data_section(allocator, buffers, reader);

                module.datas = data_section;
            },
            12 => {
                // We do not need to read the data count section right now. No Validation is done at this point, so this is not required.
                // Simply forward the reader.
                _ = try read_u32(reader);
            },

            else => return ParserError.InvalidEnumValue,
        }
    }

    if (funcs) |funcs_non_null| {
        module.funcs = funcs_non_null;
    }

    return module;
}

fn read_data_section(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) ![]abstract_syntax.Data {
    return try read_vector_allocating_pooled(abstract_syntax.Data, allocator, buffers, reader, read_data);
}

fn read_data(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) !abstract_syntax.Data {
    return switch (try read_u32(reader)) {
        0 => .{ .mode = .{ .Active = .{ .memory = 0, .offset = try read_standard_instruction(allocator, buffers, reader) } }, .init = try read_vector_u8(allocator, reader) },
        1 => .{ .mode = .Passive, .init = try read_vector_u8(allocator, reader) },
        2 => .{ .mode = .{ .Active = .{ .memory = try read_u32(reader), .offset = try read_standard_instruction(allocator, buffers, reader) } }, .init = try read_vector_u8(allocator, reader) },
        else => ParserError.InvalidEnumValue,
    };
}

fn read_element_section(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) ![]abstract_syntax.Element {
    return try read_vector_allocating_pooled(abstract_syntax.Element, allocator, buffers, reader, read_element);
}

fn read_element(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) !abstract_syntax.Element {
    const read_ref_func_op = struct {
        fn f(allocator2: Allocator, buffers2: *abstract_syntax.Buffers, reader2: anytype) !abstract_syntax.Expr {
            _ = allocator2;
            const instr = try buffers2.allocate_instruction();
            buffers2.resolve_instruction_mut(instr).?.* = .{
                .op_code = .{ .RefFunc = .{ .idx = try read_u32(reader2) } },
                .next = abstract_syntax.InstructionHandle.INVALID,
                .prev = abstract_syntax.InstructionHandle.INVALID,
            };
            return instr;
        }
    }.f;
    return switch (try read_u32(reader)) {
        0 => .{ .type = undefined, .mode = .{ .Active = .{ .table = 0, .offset = try read_standard_instruction(allocator, buffers, reader) } }, .init = try read_vector_allocating_pooled(abstract_syntax.Expr, allocator, buffers, reader, read_ref_func_op) },
        1 => .{ .type = try read_element_kind(reader), .mode = .Passive, .init = try read_vector_allocating_pooled(abstract_syntax.Expr, allocator, buffers, reader, read_ref_func_op) },
        2 => .{ .mode = .{ .Active = .{ .table = try read_u32(reader), .offset = try read_standard_instruction(allocator, buffers, reader) } }, .type = try read_element_kind(reader), .init = try read_vector_allocating_pooled(abstract_syntax.Expr, allocator, buffers, reader, read_ref_func_op) },
        3 => .{ .type = try read_element_kind(reader), .mode = .Declarative, .init = try read_vector_allocating_pooled(abstract_syntax.Expr, allocator, buffers, reader, read_ref_func_op) },
        4 => .{ .type = undefined, .mode = .{ .Active = .{ .table = 0, .offset = try read_standard_instruction(allocator, buffers, reader) } }, .init = try read_vector_allocating_pooled(abstract_syntax.Expr, allocator, buffers, reader, read_standard_instruction) },
        5 => .{ .type = try read_element_kind(reader), .init = try read_vector_allocating_pooled(abstract_syntax.Expr, allocator, buffers, reader, read_standard_instruction), .mode = .Declarative },
        6 => .{ .mode = .{ .Active = .{ .table = try read_u32(reader), .offset = try read_standard_instruction(allocator, buffers, reader) } }, .type = try read_element_kind(reader), .init = try read_vector_allocating_pooled(abstract_syntax.Expr, allocator, buffers, reader, read_standard_instruction) },
        7 => .{ .type = try read_element_kind(reader), .init = try read_vector_allocating_pooled(abstract_syntax.Expr, allocator, buffers, reader, read_standard_instruction), .mode = .Declarative },
        else => return ParserError.InvalidEnumValue,
    };
}

const CodeFragment = struct { locals: []abstract_syntax.ValueType, body: abstract_syntax.Expr };
fn read_code_section(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) ![]CodeFragment {
    return try read_vector_allocating_pooled(CodeFragment, allocator, buffers, reader, read_code_fragment);
}

fn read_code_fragment(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) !CodeFragment {
    const size = try read_u32(reader);
    var tmp_reader = std.io.limitedReader(reader, size);
    const reader2 = tmp_reader.reader();

    const locals = try read_locals(allocator, reader2);
    const expr = try read_standard_instruction(allocator, buffers, reader2);

    if (tmp_reader.bytes_left != 0) {
        return ParserError.UnexpectedFragmentSize;
    }

    return .{ .locals = locals, .body = expr };
}

fn read_locals(allocator: Allocator, reader: anytype) ![]abstract_syntax.ValueType {
    const S = struct {
        n: u32,
        t: abstract_syntax.ValueType,

        fn read(reader2: anytype) !@This() {
            return .{ .n = try read_u32(reader2), .t = try read_value_type(reader2) };
        }
    };
    const defs = try read_vector(S, allocator, reader, S.read);
    defer allocator.free(defs);
    var total_num_types: u32 = 0;

    for (defs) |def| {
        total_num_types += def.n;
    }

    const final_defs = try allocator.alloc(abstract_syntax.ValueType, total_num_types);
    var i: u32 = 0;
    for (defs) |def| {
        for (0..def.n) |_| {
            final_defs[i] = def.t;
            i += 1;
        }
    }

    return final_defs;
}

fn read_element_kind(reader: anytype) !abstract_syntax.RefType {
    switch (try read_byte(reader)) {
        0x00 => return undefined,
        else => return ParserError.InvalidEnumValue,
    }
}

fn read_start_section(reader: anytype) !abstract_syntax.ModuleStart {
    return .{ .func = try read_u32(reader) };
}

fn read_export_section(allocator: Allocator, reader: anytype) ![]abstract_syntax.Export {
    return try read_vector_allocating(abstract_syntax.Export, allocator, reader, read_export);
}

fn read_export(allocator: Allocator, reader: anytype) !abstract_syntax.Export {
    const name = try read_name(allocator, reader);
    const desc: abstract_syntax.ExportDescription = switch (try read_byte(reader)) {
        0x00 => .{ .Func = try read_u32(reader) },
        0x01 => .{ .Table = try read_u32(reader) },
        0x02 => .{ .Memory = try read_u32(reader) },
        0x03 => .{ .Global = try read_u32(reader) },
        else => return ParserError.InvalidEnumValue,
    };

    return .{ .name = name, .description = desc };
}

fn read_global_section(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) ![]abstract_syntax.Global {
    return try read_vector_allocating_pooled(abstract_syntax.Global, allocator, buffers, reader, read_global);
}

fn read_global(allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype) !abstract_syntax.Global {
    return .{ .type = try read_global_type(reader), .init = try read_standard_instruction(allocator, buffers, reader) };
}

fn read_custom_section(allocator: Allocator, reader: anytype) !void {
    const name = try read_name(allocator, reader);
    const bytes = try reader.readAllAlloc(allocator, std.math.maxInt(usize));

    _ = name;
    _ = bytes;

    return;
}

fn read_type_section(allocator: Allocator, reader: anytype) ![]abstract_syntax.FuncType {
    const types = try read_vector_allocating(abstract_syntax.FuncType, allocator, reader, read_function_type);

    return types;
}

fn read_import(allocator: Allocator, reader: anytype) !abstract_syntax.Import {
    const mod = try read_name(allocator, reader);
    const nm = try read_name(allocator, reader);

    const desc: abstract_syntax.ImportDescription = switch (try read_byte(reader)) {
        0x00 => .{ .Func = try read_u32(reader) },
        0x01 => .{ .Table = try read_u32(reader) },
        0x02 => .{ .Memory = try read_u32(reader) },
        0x03 => .{ .Global = try read_u32(reader) },
        else => return ParserError.InvalidEnumValue,
    };

    return .{ .module = mod, .name = nm, .description = desc };
}

fn read_import_section(allocator: Allocator, reader: anytype) ![]abstract_syntax.Import {
    return try read_vector_allocating(abstract_syntax.Import, allocator, reader, read_import);
}

fn read_function_section(allocator: Allocator, reader: anytype) ![]abstract_syntax.TypeIdx {
    return try read_vector(abstract_syntax.TypeIdx, allocator, reader, read_u32);
}

fn read_table_section(allocator: Allocator, reader: anytype) ![]abstract_syntax.Table {
    return try read_vector(abstract_syntax.Table, allocator, reader, read_table);
}

fn read_table(reader: anytype) !abstract_syntax.Table {
    return abstract_syntax.Table{ .type = try read_table_type(reader) };
}

fn read_memory_section(allocator: Allocator, reader: anytype) ![]abstract_syntax.Memory {
    return try read_vector(abstract_syntax.Memory, allocator, reader, read_memory);
}

fn read_memory(reader: anytype) !abstract_syntax.Memory {
    return .{ .type = try read_memory_type(reader) };
}

fn read_f32(reader: anytype) !f32 {
    var arr: [4]u8 = undefined;
    try reader.readNoEof(&arr);

    const i: u32 = (@as(u32, arr[3]) << 24) | (@as(u32, arr[2]) << 16) | (@as(u32, arr[1]) << 8) | @as(u32, arr[0]);

    return @as(f32, @bitCast(i));
}

fn read_f64(reader: anytype) !f64 {
    var arr: [8]u8 = undefined;
    try reader.readNoEof(&arr);

    const i: u64 = (@as(u64, arr[7]) << 56) | (@as(u64, arr[6]) << 48) | (@as(u64, arr[5]) << 40) | (@as(u64, arr[4]) << 32) | (@as(u64, arr[3]) << 24) | (@as(u64, arr[2]) << 16) | (@as(u64, arr[1]) << 8) | @as(u64, arr[0]);

    return @as(f64, @bitCast(i));
}

fn read_memarg(reader: anytype) !abstract_syntax.MemArg {
    return .{
        .offset = try read_u32(reader),
        .@"align" = try read_u32(reader),
    };
}

fn read_if_block(buffers: *abstract_syntax.Buffers, allocator: Allocator, reader: anytype) !abstract_syntax.OpCode {
    const bt = try read_block_type(reader);
    const body = try read_expr(buffers, allocator, reader);
    const el = if (!body.was_else) abstract_syntax.InstructionHandle.INVALID else try read_standard_instruction(allocator, buffers, reader);
    return .{ .IfElse = .{ .blocktype = bt, .body = body.instr, .elseBody = el } };
}

test "Read Unreachable Op" {
    const buffer: []const u8 = &.{0x00};
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const allocator = std.testing.failing_allocator;
    var instructions = @as([4096]abstract_syntax.Instruction, undefined);
    var buffers: abstract_syntax.Buffers = .{
        .instructions = &instructions,
        .instructions_next = 0,
    };
    const result = try read_opcode(&buffers, allocator, &reader);
    const expected: OpCodeResult = .{ .RealOpCode = .Unreachable };
    try std.testing.expectEqual(expected, result);
}

/// See WASM Spec 5.1.3
fn read_vector(comptime T: type, allocator: Allocator, reader: anytype, comptime callback: fn (anytype) anyerror!T) ![]T {
    const len = try read_u32(reader);
    const result = try allocator.alloc(T, len);
    errdefer allocator.free(result);
    for (result) |*element| {
        element.* = try callback(reader);
    }
    return result;
}

/// See WASM Spec 5.1.3
fn read_vector_allocating(comptime T: type, allocator: Allocator, reader: anytype, comptime callback: fn (Allocator, anytype) anyerror!T) ![]T {
    const len = try read_u32(reader);
    const result = try allocator.alloc(T, len);
    errdefer allocator.free(result);
    for (result) |*element| {
        element.* = try callback(allocator, reader);
    }
    return result;
}

/// See WASM Spec 5.1.3
inline fn read_vector_allocating_pooled(comptime T: type, allocator: Allocator, buffers: *abstract_syntax.Buffers, reader: anytype, comptime callback: fn (Allocator, *abstract_syntax.Buffers, anytype) anyerror!T) ![]T {
    const len = try read_u32(reader);
    const result = try allocator.alloc(T, len);
    for (result) |*element| {
        element.* = try @call(.always_inline, callback, .{ allocator, buffers, reader });
    }
    return result;
}

test "Read U32 Vector" {
    try test_with_allocator(struct {
        fn f(input_allocator: Allocator) !void {
            var allocator = input_allocator;
            const buffer: []const u8 = &.{ 0x03, 0x03, 0x03, 0x03 };
            var stream = std.io.fixedBufferStream(buffer);
            var reader = stream.reader();
            const result = try read_vector(u32, allocator, &reader, read_u32);
            defer allocator.free(result);
            const expected: []const u32 = &.{ 0x03, 0x03, 0x03 };
            try std.testing.expectEqualSlices(u32, expected, result);
        }
    }.f, .{});
}

/// See WASM Spec 5.1.3
fn read_vector_u8(allocator: Allocator, reader: anytype) ![]u8 {
    const len = try read_u32(reader);
    const result = try allocator.alloc(u8, len);
    const read = try reader.readAll(result);
    if (read != len) {
        return ParserError.UnexpectedEndOfStream;
    }
    return result;
}

test "Read U8 Vector" {
    try test_with_allocator(struct {
        fn f(input_allocator: Allocator) !void {
            var allocator = input_allocator;
            const buffer: []const u8 = &.{ 0x03, 0x03, 0x03, 0x03 };
            var stream = std.io.fixedBufferStream(buffer);
            var reader = stream.reader();
            const result = try read_vector_u8(allocator, &reader);
            defer allocator.free(result);
            const expected: []const u8 = &.{ 0x03, 0x03, 0x03 };
            try std.testing.expectEqualSlices(u8, expected, result);
        }
    }.f, .{});
}

/// See WASM Spec 5.2.2
fn read_u32(reader: anytype) !u32 {
    const leb128 = std.leb;
    const result = try leb128.readULEB128(u32, reader);
    return result;
}

test "Trailing Zeros allowed u32" {
    const buffer: []const u8 = &.{ 0x83, 0x00 };
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    const result = try read_u32(&reader);
    const expected: u32 = 3;
    try std.testing.expectEqual(expected, result);
}

/// See WASM Spec 5.2.1
fn read_byte(reader: anytype) !u8 {
    return try reader.readByte();
}

fn PeekedReader(comptime UnderlyingReader: type) type {
    return struct {
        underlying_reader: UnderlyingReader,
        peek: ?u8,

        pub const Error = switch (@typeInfo(UnderlyingReader)) {
            .Pointer => |p| p.child.Error,
            else => UnderlyingReader.Error,
        };
        pub const Reader = std.io.Reader(*Self, Error, read);

        const Self = @This();

        pub fn read(self: *Self, dest: []u8) Error!usize {
            if (self.peek) |peek| {
                dest[0] = peek;
                self.peek = null;
                return 1;
            } else {
                return self.underlying_reader.read(dest);
            }
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

fn peekedReader(reader: anytype, peek: u8) PeekedReader(@TypeOf(reader)) {
    return .{ .underlying_reader = reader, .peek = peek };
}

fn read_name(allocator: Allocator, reader: anytype) ![]u8 {
    const name = try read_vector_u8(allocator, reader);

    if (!std.unicode.utf8ValidateSlice(name)) {
        return ParserError.InvalidName;
    }

    return name;
}

const ParserError = error{ UnexpectedEndOfStream, LEBTooLong, InvalidEnumValue, NonStandardInstruction, UnexpectedFragmentSize, InvalidHeader, InvalidName };

test {
    @import("std").testing.refAllDecls(@This());
}

test "Parse Simple Module - Single Function, returns 42" {
    try test_with_allocator(struct {
        fn f(input_allocator: Allocator) !void {
            var allocator = std.heap.ArenaAllocator.init(input_allocator);
            defer allocator.deinit();
            var instructions = @as([4096]abstract_syntax.Instruction, undefined);
            var buffers: abstract_syntax.Buffers = .{
                .instructions = &instructions,
                .instructions_next = 0,
            };

            const data: []const u8 = &.{ 0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11 };
            var stream = std.io.fixedBufferStream(data);
            const reader = stream.reader();

            const module = try parse(allocator.allocator(), &buffers, reader);
            _ = module;
        }
    }.f, .{});
}

// test "Comptime Parse Simple Module - Single Function, returns 42" {
//     comptime {
//         const FixedBufferAllocator = struct {
//             end_index: usize,
//             buffer: []u8,
//             space: [65536]u8,

//             const Self = @This();

//             pub fn init() Self {
//                 var s = Self{
//                     .buffer = undefined,
//                     .end_index = 0,
//                     .space = undefined,
//                 };

//                 s.buffer = &s.space;

//                 return s;
//             }

//             pub fn allocator(self: *Self) Allocator {
//                 return .{
//                     .ptr = self,
//                     .vtable = &.{
//                         .alloc = alloc,
//                         .resize = resize,
//                         .free = free,
//                     },
//                 };
//             }

//             fn alloc(ctx: *anyopaque, n: usize, log2_ptr_align: u8, ra: usize) ?[*]u8 {
//                 const self: *Self = @ptrCast(@alignCast(ctx));
//                 _ = ra;
//                 _ = log2_ptr_align;
//                 // const ptr_align = @as(usize, 1) << @as(Allocator.Log2Align, @intCast(log2_ptr_align));
//                 // const adjust_off = std.mem.alignPointerOffset(self.buffer.ptr + self.end_index, ptr_align) orelse return null;
//                 const adjust_off = 0;
//                 const adjusted_index = self.end_index + adjust_off;
//                 const new_end_index = adjusted_index + n;
//                 if (new_end_index > self.buffer.len) return null;
//                 self.end_index = new_end_index;
//                 return self.buffer.ptr + adjusted_index;
//             }

//             fn resize(
//                 ctx: *anyopaque,
//                 buf: []u8,
//                 log2_buf_align: u8,
//                 new_size: usize,
//                 return_address: usize,
//             ) bool {
//                 const self: *Self = @ptrCast(@alignCast(ctx));
//                 _ = log2_buf_align;
//                 _ = return_address;
//                 assert(@inComptime() or self.ownsSlice(buf));

//                 if (!self.isLastAllocation(buf)) {
//                     if (new_size > buf.len) return false;
//                     return true;
//                 }

//                 if (new_size <= buf.len) {
//                     const sub = buf.len - new_size;
//                     self.end_index -= sub;
//                     return true;
//                 }

//                 const add = new_size - buf.len;
//                 if (add + self.end_index > self.buffer.len) return false;

//                 self.end_index += add;
//                 return true;
//             }

//             fn free(
//                 ctx: *anyopaque,
//                 buf: []u8,
//                 log2_buf_align: u8,
//                 return_address: usize,
//             ) void {
//                 const self: *Self = @ptrCast(@alignCast(ctx));
//                 _ = log2_buf_align;
//                 _ = return_address;
//                 assert(@inComptime() or self.ownsSlice(buf));

//                 if (self.isLastAllocation(buf)) {
//                     self.end_index -= buf.len;
//                 }
//             }

//             pub fn reset(self: *Self) void {
//                 self.end_index = 0;
//             }
//         };
//         var allocator = FixedBufferAllocator.init();
//         defer allocator.deinit();
//         var instructions = @as([4096]abstract_syntax.Instruction, undefined);
//         var buffers: abstract_syntax.Buffers = .{
//             .instructions = &instructions,
//             .instructions_next = 0,
//         };

//         const data: []const u8 = &.{ 0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11 };
//         var stream = std.io.fixedBufferStream(data);
//         const reader = stream.reader();

//         const module = try parse(allocator.allocator(), &buffers, reader);
//         _ = module;
//     }
// }
