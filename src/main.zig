const r4os = @import("r4os");

const TYPE_ECHO_REPLY: u8 = 0;
const TYPE_ECHO_REQUEST: u8 = 8;

comptime {
    asm (r4os.r4dev.protocolEntriesAsm("neticmp_init", "neticmp_shutdown", "neticmp_query", "neticmp_dispatch"));
}

export fn neticmp_init(api: *const r4os.r4dev.ProtocolApi) callconv(.c) i32 {
    var ctx = r4os.r4dev.ProtocolContext.init(api);
    ctx.logInfo("NETICMP.R4P init");
    _ = ctx.registerRole("net.icmp", .net, 0);
    _ = ctx.setStatus(.active, "ICMP R4P active");
    return 0;
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
    if (buffer.data == null) return null;
    if (buffer.len < @sizeOf(r4os.abi.IcmpOp)) return null;
    return @ptrCast(@alignCast(buffer.data.?));
}

fn checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += (@as(u32, data[i]) << 8) | data[i + 1];
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @intCast(~sum & 0xFFFF);
}

fn readBe16(buf: []const u8, offset: usize) u16 {
    return (@as(u16, buf[offset]) << 8) | buf[offset + 1];
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    buf[offset] = @intCast(value >> 8);
    buf[offset + 1] = @intCast(value & 0xFF);
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
