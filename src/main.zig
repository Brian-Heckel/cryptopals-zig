const std = @import("std");
const ArrayList = std.ArrayList;
const set1 = @import("set1.zig");
const alloc = std.heap.page_allocator;

fn containsEOF(buf: []const u8) bool {
    for (buf) |b| {
        if (b == 4) {
            return true;
        }
    }
    return false;
}

fn set1Challenge3() !void {
    const stdin = std.io.getStdIn().reader();
    const input = try stdin.readAllAlloc(std.heap.page_allocator, 8192);
    const hex_encoded = input[0 .. input.len - 1];
    std.debug.print("Input Hex len {d}\n", .{hex_encoded.len});
    const tmp_encoded = try alloc.alloc(u8, hex_encoded.len - 1);
    defer alloc.free(tmp_encoded);
    const encoded = try std.fmt.hexToBytes(tmp_encoded, hex_encoded);

    const key = try set1.single_byte_key(encoded);
    set1.xor_single_byte(key, encoded);
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Key: {c}\n", .{key});
    try stdout.print("Decoded: {s}\n", .{encoded});

    try bw.flush(); // don't forget to flush!
}
fn set1Challenge4() !void {
    const stdin = std.io.getStdIn().reader();
    const rawInput = try stdin.readAllAlloc(std.heap.page_allocator, 20000);
    var lines = std.mem.splitSequence(u8, rawInput[0 .. rawInput.len - 1], "\n");
    const EncodedEntry = struct {
        decoded_line: []u8,
        key: u8,
        score: f64,
    };
    var scored_entries = ArrayList(EncodedEntry).init(std.heap.page_allocator);
    defer scored_entries.deinit();
    while (lines.next()) |line| {
        const tmp_encoded = try alloc.alloc(u8, line.len);
        const encoded = try std.fmt.hexToBytes(tmp_encoded, line);
        const key = try set1.single_byte_key(encoded);
        set1.xor_single_byte(key, encoded);
        const score = try set1.scoreText(encoded);
        try scored_entries.append(.{ .decoded_line = encoded, .key = key, .score = score });
    }

    // find the max score
    var max_score = scored_entries.items[0];
    for (scored_entries.items) |entry| {
        if (containsEOF(entry.decoded_line)) {
            continue;
        }
        if (entry.score > max_score.score) {
            max_score = entry;
        }
    }
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();
    try stdout.print("Best Score: {d}\n", .{max_score.score});
    try stdout.print("Best Key: {c}\n", .{max_score.key});
    try stdout.print("Best Decoded: {s}\n", .{max_score.decoded_line});
    try bw.flush(); // don't forget to flush!
}

fn set1Challenge6() !void {
    const stdin = std.io.getStdIn().reader();
    const rawInput = try stdin.readAllAlloc(std.heap.page_allocator, 20000);
    const base_64_encoded = rawInput[0 .. rawInput.len - 1];
    const base_64_decoder = std.base64.standard.Decoder;
    const size = try base_64_decoder.calcSizeForSlice(base_64_encoded);
    const encoded_input = try alloc.alloc(u8, size);
    try base_64_decoder.decode(encoded_input, base_64_encoded);
    const key = try set1.breakRepeatingKeyXor(encoded_input);
    const decoded = try set1.repeating_key_xor(key, encoded_input);
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();
    try stdout.print("Key: {s}\n", .{key});
    try stdout.print("Decoded: {s}\n", .{decoded});
    try bw.flush(); // don't forget to flush!
}

fn set1Challenge7() !void {
    const stdin = std.io.getStdIn().reader();
    const rawInput = try stdin.readAllAlloc(std.heap.page_allocator, 20000);
    const base_64_encoded = rawInput[0 .. rawInput.len - 1];
    const base_64_decoder = std.base64.standard.Decoder;
    const size = try base_64_decoder.calcSizeForSlice(base_64_encoded);
    const encoded = try alloc.alloc(u8, size);
    defer alloc.free(encoded);
    try base_64_decoder.decode(encoded, base_64_encoded);
    const key = [_]u8{ 'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E' };
    const decrypted = try set1.aes_ecb_decrypt(key, encoded);

    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();
    try stdout.print("Decoded: {s}\n", .{decrypted});
    try bw.flush(); // don't forget to flush!
}

fn set1Challenge8() !void {
    const stdin = std.io.getStdIn();
    var buffered = std.io.bufferedReader(stdin.reader());
    var reader = buffered.reader();

    var encrypted = std.ArrayList(u8).init(alloc);
    defer encrypted.deinit();
    var seen = std.ArrayList([]const u8).init(alloc);
    defer seen.deinit();

    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    var line_no: u32 = 0;

    while (true) {
        reader.streamUntilDelimiter(encrypted.writer(), '\n', null) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };

        // check if any two 16 byte blocks are the same
        var match_blocks: bool = false;
        var block_window = std.mem.window(u8, encrypted.items, 16, 16);
        while (block_window.next()) |block| {
            if (block.len != 16) {
                break;
            }
            for (seen.items) |seen_block| {
                if (std.mem.eql(u8, seen_block, block)) {
                    match_blocks = true;
                    // todo record which line the encoded block is
                    try stdout.print("Seen Matching Block at line: {}\n", .{line_no});
                    break;
                }
            }
            try seen.append(block);
        }
        encrypted.clearRetainingCapacity();
        seen.clearRetainingCapacity();
        line_no += 1;
    }
    try bw.flush(); // don't forget to flush!
}

pub fn main() !void {
    var args = try std.process.argsWithAllocator(std.heap.page_allocator);
    _ = args.next().?;
    const set = args.next().?;
    const challenge = args.next().?;

    switch (set[0]) {
        '1' => {
            switch (challenge[0]) {
                '3' => {
                    try set1Challenge3();
                },
                '4' => {
                    try set1Challenge4();
                },
                '6' => {
                    try set1Challenge6();
                },
                '7' => {
                    try set1Challenge7();
                },
                '8' => {
                    try set1Challenge8();
                },
                else => {},
            }
        },
        else => {},
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
