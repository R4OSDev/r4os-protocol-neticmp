const r4os = @import("r4os");

const TYPE_ECHO_REPLY: u8 = 0;
const TYPE_ECHO_REQUEST: u8 = 8;

comptime {
    if (!@import("builtin").is_test) asm (r4os.technical2.protocolEntriesAsm("neticmp_init", "neticmp_shutdown", "neticmp_query", "neticmp_dispatch"));
}

export fn neticmp_init(api: *const r4os.technical2.abi.ProtocolApi2) callconv(.c) i32 {
    const view = r4os.technical2.Protocol.init(api) orelse return r4os.abi.network_error_backend;
    const log = view.function("log_info") orelse return r4os.abi.err_no_fn;
    const register = view.function("register_role") orelse return r4os.abi.err_no_fn;
    const status = view.function("set_status") orelse return r4os.abi.err_no_fn;
    log("NETICMP.R4P init");
    const registered = register("net.icmp", @intFromEnum(r4os.abi.ProtocolCategory.net), 0);
    if (registered != 0) return registered;
    return status(@intFromEnum(r4os.abi.ProtocolState.active), "ICMP R4P active");
}

export fn neticmp_shutdown() callconv(.c) i32 {
    return 0;
}

export fn neticmp_query(out: *r4os.abi.ProtocolStatus) callconv(.c) i32 {
    out.* = .{
        .state = @intFromEnum(r4os.abi.ProtocolState.active),
        .flags = 0,
        .last_error = 0,
        .reserved = 0,
        .note = note("ICMP R4P ready"),
    };
    return 0;
}

export fn neticmp_dispatch(op: u32, in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) callconv(.c) i32 {
    _ = out_buffer;
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.icmp_op_handle_rx => inspect(request),
        r4os.abi.icmp_op_handle_tx => inspect(request),
        r4os.abi.icmp_op_build_echo_request => buildEchoRequest(request),
        r4os.abi.icmp_op_build_echo_reply => buildEchoReply(request),
        r4os.abi.icmp_op_is_echo_request => inspect(request),
        else => return -4,
    }
    return request.result;
}

fn inspect(request: *r4os.abi.IcmpOp) void {
    request.flags = 0;
    if (request.payload_len < 8 or request.payload_len > request.payload.len) {
        request.result = r4os.abi.icmp_result_short;
        return;
    }
    const payload = request.payload[0..@intCast(request.payload_len)];
    if (checksum(payload) != 0) {
        request.result = r4os.abi.icmp_result_checksum;
        return;
    }
    request.typ = payload[0];
    request.code = payload[1];
    request.ident = readBe16(payload, 4);
    request.seq = readBe16(payload, 6);
    if (request.typ == TYPE_ECHO_REQUEST and request.code == 0) request.flags |= r4os.abi.icmp_flag_echo_request;
    if (request.typ == TYPE_ECHO_REPLY and request.code == 0) request.flags |= r4os.abi.icmp_flag_echo_reply;
    request.result = r4os.abi.icmp_result_ok;
}

fn buildEchoRequest(request: *r4os.abi.IcmpOp) void {
    const data = "R4OSPING";
    const len = 8 + data.len;
    if (request.payload.len < len) {
        request.result = r4os.abi.icmp_result_buffer_small;
        return;
    }
    var i: usize = 0;
    while (i < len) : (i += 1) request.payload[i] = 0;
    request.payload[0] = TYPE_ECHO_REQUEST;
    request.payload[1] = 0;
    writeBe16(request.payload[0..], 4, request.ident);
    writeBe16(request.payload[0..], 6, request.seq);
    i = 0;
    while (i < data.len) : (i += 1) request.payload[8 + i] = data[i];
    writeBe16(request.payload[0..], 2, checksum(request.payload[0..len]));
    request.payload_len = @intCast(len);
    request.typ = TYPE_ECHO_REQUEST;
    request.code = 0;
    request.flags = r4os.abi.icmp_flag_echo_request;
    request.result = r4os.abi.icmp_result_ok;
}

fn buildEchoReply(request: *r4os.abi.IcmpOp) void {
    if (request.payload_len < 8 or request.payload_len > request.payload.len) {
        request.result = r4os.abi.icmp_result_short;
        return;
    }
    const len: usize = @intCast(request.payload_len);
    request.payload[0] = TYPE_ECHO_REPLY;
    request.payload[1] = 0;
    request.payload[2] = 0;
    request.payload[3] = 0;
    writeBe16(request.payload[0..], 2, checksum(request.payload[0..len]));
    request.typ = TYPE_ECHO_REPLY;
    request.code = 0;
    request.ident = readBe16(request.payload[0..], 4);
    request.seq = readBe16(request.payload[0..], 6);
    request.flags = r4os.abi.icmp_flag_echo_reply;
    request.result = r4os.abi.icmp_result_ok;
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.IcmpOp {
    // The legacy operation is an exclusive in/out native record, despite
    // the const transport metadata. No packet bytes are native-cast here.
    const native = r4os.native_protocol_view;
    var metadata = buffer.*;
    const view = native.InOut(r4os.abi.IcmpOp).init(&metadata, native.Policy.record(r4os.abi.IcmpOp, .inout, .prefix)) catch return null;
    return view.value;
}

fn checksum(data: []const u8) u16 {
    var value: r4os.internet_checksum.Checksum16 = .{};
    value.add(data) catch unreachable;
    return value.finish() catch unreachable;
}

fn readBe16(buf: []const u8, offset: usize) u16 {
    var reader = r4os.binary_cursor.Reader.init(buf) catch unreachable;
    _ = reader.take(offset) catch unreachable;
    return reader.readInt(u16, .big) catch unreachable;
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    var writer = r4os.binary_cursor.Writer.init(buf) catch unreachable;
    writer.position = offset;
    writer.writeInt(u16, value, .big) catch unreachable;
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
