//
// THIS FILE IMPLEMENTS THE WASM SPEC CHAPTER 2 VERSION 2.0 (DRAFT 2023-06-14).
//

const mem = @import("mem.zig");
const assert = @import("assert.zig");

/// See WASM Spec: 2.5
pub const Module = struct {
    types: []const Type,
    funcs: []const Func,
    tables: []const Table,
    memories: []const Memory,
    globals: []const Global,
    elements: []const Element,
    datas: []const Data,
    start: ?ModuleStart,
    imports: []const Import,
    exports: []const Export,

    const Self = @This();
};

const HandleBase = u32;

/// See WASM Spec 2.5.1
pub const TypeIdx = HandleBase;
/// See WASM Spec 2.5.1
pub const FuncIdx = HandleBase;
/// See WASM Spec 2.5.1
pub const TableIdx = HandleBase;
/// See WASM Spec 2.5.1
pub const MemoryIdx = HandleBase;
/// See WASM Spec 2.5.1
pub const GlobalIdx = HandleBase;
/// See WASM Spec 2.5.1
pub const ElementIdx = HandleBase;
/// See WASM Spec 2.5.1
pub const DataIdx = HandleBase;
/// See WASM Spec 2.5.1
pub const LocalIdx = HandleBase;
/// See WASM Spec 2.5.1
pub const LabelIdx = HandleBase;

// TODO(JIM-12): Add functions to resolve Idx to *T, do note that these are not simply indices into the respective arrays!

pub const Uninterpreted32 = struct {
    inner: u32,
    pub fn into_signed(self: @This()) i32 {
        return @bitCast(self.inner);
    }
    pub fn into_unsigned(self: @This()) u32 {
        return @bitCast(self.inner);
    }
};
pub const Uninterpreted64 = struct { inner: u64 };

/// See WASM Spec 2.3.1
pub const NumType = enum(u4) { I32, I64, F32, F64 };

/// See WASM Spec 2.3.2
pub const VecType = enum(u0) { V128 };

/// See WASM Spec 2.3.3
pub const RefType = u0; // TODO(JIM-13): Model References

/// See WASM Spec 2.3.4
pub const ValueType = union(enum) { Num: NumType, Vec: VecType, Ref: RefType };

/// See WASM Spec 2.3.5
pub const ResultType = []const ValueType;

/// See WASM Spec 2.3.6
pub const FuncType = struct {
    args: ResultType,
    result: ResultType,
};

/// See WASM Spec 2.5.2
pub const Type = FuncType;

/// See WASM Spec 2.5.3
pub const Func = struct { type: TypeIdx, locals: []const ValueType, body: Expr };

/// See WASM Spec 2.5.4
pub const Table = struct { type: TableType };

/// See WASM Spec 2.3.9
pub const TableType = struct { limits: Limits, reftype: RefType };

/// See WASM Spec 2.3.7
pub const Limits = struct { min: u32, max: ?u32 };

/// See WASM Spec 2.5.5.
pub const Memory = struct { type: MemoryType };

/// See WASM Spec 2.3.8
pub const MemoryType = struct { limits: Limits };

/// See WASM Spec 2.5.6
pub const Global = struct { type: GlobalType, init: Expr };

/// See WASM Spec 2.3.10
pub const GlobalType = struct { mutability: Mutability, valueType: ValueType };
pub const Mutability = union(enum) {
    @"const": void,
    @"var": void,
};

/// See WASM Spec 2.5.7
pub const Element = struct { type: RefType, init: []const Expr, mode: ElementMode };
pub const ElementMode = union(enum) { Passive: void, Active: struct { table: TableIdx, offset: ConstantExpr }, Declarative: void };

/// See WASM Spec 2.5.8
pub const Data = struct { init: []const u8, mode: DataMode };
pub const DataMode = union(enum) { Passive: void, Active: struct { memory: MemoryIdx, offset: ConstantExpr } };

/// See WASM Spec 2.5.9
pub const ModuleStart = struct { func: FuncIdx };

/// See WASM Spec 2.5.10
pub const Export = struct { name: Name, description: ExportDescription };
pub const ExportDescription = union(enum) { Func: FuncIdx, Table: TableIdx, Memory: MemoryIdx, Global: GlobalIdx };

/// See WASM Spec 2.2.5
pub const Name = []const u8; // TODO: Should this be @import("std/unicode.zig").Utf8View?;

/// See WASM Spec 2.5.11
pub const Import = struct { module: Name, name: Name, description: ImportDescription };
pub const ImportDescription = union(enum) { Func: FuncIdx, Table: TableIdx, Memory: MemoryIdx, Global: GlobalIdx };

/// See WASM Spec 2.4.9
pub const Expr = InstructionHandle; // The `end` marker is omitted, as it is considered unhelpful.
pub const ConstantExpr = Expr; // TODO: For now

pub const Instruction = struct {
    op_code: OpCode,
    next: InstructionHandle,
    prev: InstructionHandle,
};

pub const InstructionHandle = enum(u32) { INVALID = std.math.maxInt(u32), _ };

pub const Buffers = struct {
    instructions: []Instruction,
    instructions_next: u32,

    pub fn allocate_instruction(self: *Buffers) !InstructionHandle {
        self.instructions_next += 1;
        if (self.instructions_next >= self.instructions.len) {
            assert.fail("TODO: Reallocate instruction data as necessary", .{});
        }
        return @enumFromInt(self.instructions_next - 1);
    }

    pub fn free_instruction(self: *Buffers, handle: InstructionHandle) void {
        // TODO: Implement free with a double headed list or something...
        _ = self;
        _ = handle;
    }

    pub fn resolve_instruction(self: *const Buffers, handle: InstructionHandle) ?*const Instruction {
        if (handle == InstructionHandle.INVALID) return null;

        return &self.instructions[@intFromEnum(handle)];
    }

    pub fn resolve_instruction_mut(self: *const Buffers, handle: InstructionHandle) ?*Instruction {
        if (handle == InstructionHandle.INVALID) return null;

        return &self.instructions[@intFromEnum(handle)];
    }
};

fn resolve_instruction(handle: InstructionHandle) ?*Instruction {
    _ = handle;
    @panic("TODO");
}

fn resolve_instruction_const(handle: InstructionHandle) ?*const Instruction {
    _ = handle;
    @panic("TODO");
}

comptime {
    assert.ensure_size(Instruction, 40);
}

/// See WASM Spec 2.4
pub const OpCode = MergeUnions(&.{
    Instruction_Other,
    Instruction_Other_Prefix_Int,
    Instruction_Other_Prefix_Float,
    IUnOp,
    IBinOp,
    FUnOp,
    FBinOp,
    ITestOp,
    IRelOp,
    FRelOp,
    ReferenceInstructions,
    ParametricInstructions,
    VariableInstructions,
    TableInstructions,
    MemoryInstructions,
    ControlInstructions,
});
const Instruction_Other_Prefix_Int = FillTemplatedAllPrefixed(false, union(enum) {
    Extend8Signed,
    Extend16Signed,
    TruncateSaturateF32Signed,
    TruncateSaturateF64Signed,
    TruncateSaturateF32Unsigned,
    TruncateSaturateF64Unsigned,
    TruncateF32Signed,
    TruncateF64Signed,
    TruncateF32Unsigned,
    TruncateF64Unsigned,
    Const: struct { value: u0 },
});

const Instruction_Other = union(enum) {
    I32WrapI64,
    I64Extend32Signed,
    I64Extend32Unsigned,
    F32DemoteF64,
    F64PromoteF32,
    I32ReinterpretF32,
    I64ReinterpretF64,
    F32ReinterpretI32,
    F64ReinterpretI64,
};

const Instruction_Other_Prefix_Float = FillTemplatedAllPrefixed(true, union(enum) {
    Const: struct { value: u0 },
    ConvertI32Signed,
    ConvertI32Unsigned,
    ConvertI64Signed,
    ConvertI64Unsigned,
});
// NOTE: The spec specifies the below *without* the "prefix", and includes the prefix in the above instruction definition instead.
// For clarity we prefer Including the prefix below, as the variables are never re-used anyways.

// BEGIN WASM Spec 2.4.1

pub const IUnOp = FillTemplatedAllPrefixed(false, union(enum) { Clz, Ctz, PopCnt });
pub const IBinOp = FillTemplatedAllPrefixed(false, union(enum) { Add, Sub, Mul, DivUnsigned, DivSigned, RemUnsigned, RemSigned, And, Or, Xor, ShiftLeft, ShiftRightUnsigned, ShiftRightSigned, RotateLeft, RotateRight });
pub const FUnOp = FillTemplatedAllPrefixed(true, union(enum) { Abs, Neg, Sqrt, Ceil, Floor, Trunc, Nearest });
pub const FBinOp = FillTemplatedAllPrefixed(true, union(enum) { Add, Sub, Mul, Div, Min, Max, CopySign });
pub const ITestOp = FillTemplatedAllPrefixed(false, union(enum) { EqualZero });
pub const IRelOp = FillTemplatedAllPrefixed(false, union(enum) { Equal, NotEqual, LessThanSigned, LessThanUnsigned, GreaterThanSigned, GreaterThanUnsigned, LessThanOrEqualSigned, LessThanOrEqualUnsigned, GreaterThanOrEqualSigned, GreaterThanOrEqualUnsigned });
pub const FRelOp = FillTemplatedAllPrefixed(true, union(enum) { Equal, NotEqual, LessThan, GreaterThan, LessThanOrEqual, GreaterThanOrEqual });

// END WASM Spec 2.4.1

// TODO: Vector Instructions

/// See WASM Spec 2.4.3
pub const ReferenceInstructions = union(enum) {
    RefNull: struct { type: RefType },
    RefIsNull,
    RefFunc: struct { idx: FuncIdx },
};

/// See WASM Spec 2.4.4
pub const ParametricInstructions = union(enum) { Drop, Select: struct { type: ?[]const ValueType } };

/// See WASM Spec 2.4.5
pub const VariableInstructions = union(enum) {
    LocalGet: struct { idx: LocalIdx },
    LocalSet: struct { idx: LocalIdx },
    LocalTee: struct { idx: LocalIdx },
    GlobalGet: struct { idx: GlobalIdx },
    GlobalSet: struct { idx: GlobalIdx },
};

/// See WASM Spec 2.4.6
pub const TableInstructions = union(enum) {
    TableGet: struct { idx: TableIdx },
    TableSet: struct { idx: TableIdx },
    TableSize: struct { idx: TableIdx },
    TableGrow: struct { idx: TableIdx },
    TableFill: struct { idx: TableIdx },
    TableCopy: struct { src: TableIdx, dest: TableIdx },
    TableInit: struct { idx: TableIdx, element: ElementIdx },
    ElementDrop: struct { idx: ElementIdx },
};

/// See WASM Spec 2.4.7
pub const MemoryInstructions = MergeUnions(&.{ MemoryInstructions_Other, MemoryInstructions_Prefix_I, MemoryInstructions_Prefix_F, MemoryInstructions_Vectors });
/// A MemArg for use with various MemoryInstructions.
/// See WASM SPec 2.4.7
/// align is represented as the exponent of a power of 2.
pub const MemArg = struct { offset: u32, @"align": u32 };
const MemoryInstructions_Prefix_I = FillTemplatedAllPrefixed(false, union(enum) {
    Load: struct { memArg: MemArg },
    Store: struct { memArg: MemArg },
    Load8Signed: struct { memArg: MemArg },
    Load8Unsigned: struct { memArg: MemArg },
    Load16Signed: struct { memArg: MemArg },
    Load16Unsigned: struct { memArg: MemArg },
    Store8: struct { memArg: MemArg },
    Store16: struct { memArg: MemArg },
});

const MemoryInstructions_Prefix_F = FillTemplatedAllPrefixed(true, union(enum) {
    Load: struct { memArg: MemArg },
    Store: struct { memArg: MemArg },
});

const MemoryInstructions_Vectors = union(enum) {
    // TODO: Vector Instructions
};

const MemoryInstructions_Other = union(enum) {
    MemorySize,
    MemoryGrow,
    MemoryFill,
    MemoryCopy,
    MemoryInit: struct { idx: DataIdx },
    DataDrop: struct { idx: DataIdx },
    I64Load32Signed: struct { memArg: MemArg },
    I64Load32Unsigned: struct { memArg: MemArg },
    I64Store32: struct { memArg: MemArg },
};

/// See WASM Spec 2.4.8
pub const ControlInstructions = union(enum) {
    Nop,
    Unreachable,
    Block: struct { blocktype: BlockType, body: InstructionHandle }, // The end marker is omitted
    Loop: struct { blocktype: BlockType, body: InstructionHandle },
    IfElse: struct { blocktype: BlockType, body: InstructionHandle, elseBody: InstructionHandle },
    Branch: struct { idx: LabelIdx },
    BranchIf: struct { idx: LabelIdx },
    BranchTable: struct { table: []const LabelIdx, fallback: LabelIdx },
    Return,
    Call: struct { idx: FuncIdx },
    CallIndirect: struct { table: TableIdx, type: TypeIdx },
};

/// See WASM Spec 2.4.8
pub const BlockType = union(enum) {
    TypeIndex: TypeIdx,
    Inline: ?ValueType,
};

const std = @import("std");

const BitWidth = enum { B32, B64 };

fn FillTemplatedAllPrefixed(comptime is_float: bool, comptime Template: type) type {
    return MergeUnions(&.{ MakePrefixedBitWidth(is_float, BitWidth.B32, Template), MakePrefixedBitWidth(is_float, BitWidth.B64, Template) });
}

fn TransformTemplatedType(comptime bw: BitWidth, comptime is_float: bool, comptime T: type) type {
    comptime {
        return switch (@typeInfo(T)) {
            .Struct => |s| if (s.fields.len == 1) {
                var new_fields: [s.fields.len]std.builtin.Type.StructField = undefined;
                for (&new_fields, s.fields) |*new_field, field| {
                    const new_type = TransformTemplatedType(bw, is_float, field.type);
                    new_field.* = .{
                        .type = new_type,
                        .name = field.name,
                        .default_value = field.default_value,
                        .is_comptime = field.is_comptime,
                        .alignment = @alignOf(new_type),
                    };
                }
                return @Type(.{ .Struct = .{ .layout = s.layout, .backing_integer = s.backing_integer, .fields = &new_fields, .decls = s.decls, .is_tuple = s.is_tuple } });
            } else T,
            .Int => |int| {
                return if (int.bits == 0) switch (bw) {
                    BitWidth.B32 => if (is_float) f32 else u32,
                    BitWidth.B64 => if (is_float) f64 else u64,
                } else T;
            },
            else => T,
        };
    }
}

fn MakePrefixedBitWidth(comptime is_float: bool, comptime bw: BitWidth, comptime Template: type) type {
    comptime {
        var info = @typeInfo(Template).Union;

        var new_fields: [info.fields.len]std.builtin.Type.UnionField = undefined;
        for (&new_fields, info.fields) |*new_field, field| {
            var new_type = field.type;
            var new_align = field.alignment;
            var new_name: [field.name.len + 3:0]u8 = undefined;
            @memcpy(new_name[3..], field.name);
            @memcpy(new_name[1..3], switch (bw) {
                BitWidth.B32 => "32",
                BitWidth.B64 => "64",
            });
            new_name[0] = if (is_float) 'F' else 'I';

            new_type = TransformTemplatedType(bw, is_float, new_type);
            new_align = @alignOf(new_type);

            new_field.* = .{
                .name = &new_name,
                .type = new_type,
                .alignment = new_align,
            };
        }
        info.fields = &new_fields;
        info.tag_type = RebuildTagType(info.fields);
        const final_type = @Type(.{ .Union = info });
        return final_type;
    }
}

// fn FillTemplatedBitWidth(comptime bw: BitWidth, comptime Template: type) type {
//     comptime {
//         var info = @typeInfo(Template).Union;

//         var new_fields: [info.fields.len]std.builtin.Type.UnionField = undefined;
//         for (&new_fields, info.fields) |*new_field, field| {
//             var new_type = field.type;
//             var new_align = field.alignment;
//             var new_name: [field.name.len]u8 = undefined;
//             @memset(&new_name, 0);
//             if (std.mem.replace(u8, field.name, "I__", switch (bw) {
//                 BitWidth.B32 => "I32",
//                 BitWidth.B64 => "I64",
//             }, &new_name) > 0) {
//                 new_type = TransformTemplatedType(bw, false, new_type);
//                 new_align = @alignOf(new_type);
//             } else if (std.mem.replace(u8, field.name, "F__", switch (bw) {
//                 BitWidth.B32 => "F32",
//                 BitWidth.B64 => "F64",
//             }, &new_name) > 0) {
//                 new_type = TransformTemplatedType(bw, true, new_type);
//                 new_align = @alignOf(new_type);
//             }

//             new_field.* = .{
//                 .name = &new_name,
//                 .type = new_type,
//                 .alignment = new_align,
//             };
//         }
//         info.fields = &new_fields;
//         info.tag_type = RebuildTagType(info.fields);
//         const final_type = @Type(.{ .Union = info });
//         return final_type;
//     }
// }

const LogUnions = false;

fn MergeUnions(comptime Unions: []const type) type {
    comptime {
        var fields: []const std.builtin.Type.UnionField = &.{};
        if (LogUnions) {
            @compileLog("Merging:");
        }
        for (Unions) |Union| {
            if (LogUnions) {
                @compileLog("\t", @typeName(Union), " - ", @sizeOf(Union));
                for (@typeInfo(Union).Union.fields) |f| {
                    @compileLog("\t\t", f.name, @typeName(f.type), @sizeOf(f.type));
                }
            }
            fields = fields ++ @typeInfo(Union).Union.fields;
        }
        var decls: [0]std.builtin.Type.Declaration = undefined;
        const T = @Type(.{ .Union = .{
            .layout = std.builtin.Type.ContainerLayout.auto,
            .tag_type = RebuildTagType(fields),
            .fields = fields,
            .decls = &decls,
        } });

        if (LogUnions) {
            @compileLog("Final: ", @sizeOf(T));
        }

        return T;
    }
}

fn RebuildTagType(comptime fields: []const std.builtin.Type.UnionField) type {
    if (fields.len == 0) {
        return enum {};
    }

    var tag_fields: [fields.len]std.builtin.Type.EnumField = undefined;
    for (&tag_fields, fields, 0..) |*tag_field, field, value| {
        tag_field.* = .{
            .name = field.name,
            .value = value,
        };
    }
    return @Type(.{ .Enum = .{
        .tag_type = std.math.IntFittingRange(0, tag_fields.len - 1),
        .fields = &tag_fields,
        .decls = &.{},
        .is_exhaustive = true,
    } });
}

test {
    @import("std").testing.refAllDecls(@This());
    const A: IUnOp = .I32Clz;
    _ = A;
    const B: IUnOp = .I64Clz;
    _ = B;
    const C: Instruction = .{ .op_code = .{ .I32Const = .{ .value = 123 } }, .next = InstructionHandle.INVALID, .prev = InstructionHandle.INVALID };
    _ = C;
    const D: Instruction = .{ .op_code = .{ .F32Const = .{ .value = 123.0 } }, .next = InstructionHandle.INVALID, .prev = InstructionHandle.INVALID };
    _ = D;
}
