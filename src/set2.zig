const std = @import("std");
const assert = std.debug.assert;

pub fn padBlock(block: []const u8, block_size: usize) ![]u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var padded_block = try allocator.alloc(u8, block_size);
    assert(block.len < block_size);
    const pad = block_size - block.len;
    const pad_byte: u8 = @intCast(pad);
    var i: usize = 0;
    while (i < block_size) : (i += 1) {
        if (i < block.len) {
            padded_block[i] = block[i];
        } else {
            padded_block[i] = pad_byte;
        }
    }
    return padded_block;
}

test "PKCS Padding" {
    const unpadded_block = "YELLOW SUBMARINE";
    const padded_block = try padBlock(unpadded_block[0..16], 20);
    const expected = "YELLOW SUBMARINE\x04\x04\x04\x04";
    try std.testing.expectEqualSlices(u8, expected, padded_block);
}
