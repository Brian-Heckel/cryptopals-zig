const std = @import("std");
const Allocator = std.mem.Allocator;
const alloc = std.heap.page_allocator;
const expect = std.testing.expect;
const eql = std.mem.eql;
const fmt = std.fmt;
const assert = std.debug.assert;
const aes = std.crypto.core.aes;

fn hex_to_base64(hex_string: []const u8) ![]u8 {
    // Decode hex string
    const bytes = try alloc.alloc(u8, hex_string.len);
    const hex_bytes = try fmt.hexToBytes(bytes, hex_string);
    // Encode decoded bytes to base64
    const encoder = std.base64.standard.Encoder;
    const calc_size = encoder.calcSize(hex_bytes.len);
    const dest = try alloc.alloc(u8, calc_size);
    _ = encoder.encode(dest, hex_bytes);
    return dest;
}

fn fixed_xor(buf1: []u8, buf2: []u8) ![]u8 {
    var result_buf = try alloc.alloc(u8, buf1.len);
    var i: usize = 0;
    for (buf1, buf2) |b1, b2| {
        result_buf[i] = b1 ^ b2;
        i += 1;
    }
    return result_buf;
}

/// If the byte is an uppercase ascii turn it into
/// the lowercase byte otherwise return the same byte
fn turnLowercase(byte: u8) u8 {
    switch (byte) {
        'A'...'Z' => {
            return byte | 0x20;
        },
        'a'...'z' => {
            return byte;
        },
        else => {
            return byte;
        },
    }
}

pub fn scoreText(text: []const u8) !f64 {
    var map = std.AutoHashMap(u8, f64).init(alloc);
    defer map.deinit();
    // ETAOIN SHRDLU
    try map.put('u', 1.0);
    try map.put('l', 2.0);
    try map.put('d', 3.0);
    try map.put('r', 4.0);
    try map.put('h', 5.0);
    try map.put('s', 6.0);
    try map.put(' ', 7.0);
    try map.put('n', 8.0);
    try map.put('i', 9.0);
    try map.put('o', 10.0);
    try map.put('a', 11.0);
    try map.put('t', 12.0);
    try map.put('a', 13.0);
    var total_score: f64 = 0.0;
    for (text) |c| {
        const cur_score = map.get(c) orelse 0.0;
        total_score += cur_score;
    }
    return total_score;
}

pub fn xor_single_byte(key: u8, code: []u8) void {
    for (code, 0..) |_, i| {
        code[i] ^= key;
    }
}

/// Given some encoded bytes from a single byte xor chipher
/// find the key
pub fn single_byte_key(encoded: []u8) !u8 {
    const KeyScore = struct { key: u8, score: f64 };
    var best: KeyScore = .{ .key = 0, .score = std.math.floatMax(f64) * -1.0 };
    for (0..256) |i| {
        const key: u8 = @intCast(i);
        xor_single_byte(key, encoded);
        const score = try scoreText(encoded);
        xor_single_byte(key, encoded);
        if (best.score < score) {
            best = .{ .key = key, .score = score };
        }
    }
    return best.key;
}

pub fn repeating_key_xor(key: []const u8, plaintext: []const u8) ![]u8 {
    const ciphertext = try alloc.alloc(u8, plaintext.len);
    for (plaintext, 0..) |byte, i| {
        ciphertext[i] = byte ^ key[i % key.len];
    }
    return ciphertext;
}

fn popcountByte(byte: u8) u8 {
    // using Brian Kernighan's way in bithacks
    var v: u8 = byte;
    var c: u8 = 0;
    while (v != 0) : (c += 1) {
        v &= v - 1;
    }
    return c;
}

fn hammingDistance(bytes1: []const u8, bytes2: []const u8) u32 {
    var dist: u32 = 0;
    assert(bytes1.len == bytes2.len);
    for (bytes1, bytes2) |b1, b2| {
        dist += @as(u32, popcountByte(b1 ^ b2));
    }
    return dist;
}

fn fourHammingBlocks(src: []u8, keysize: u64) f64 {
    assert(keysize * 4 < src.len);
    var total_hamming_dist: u64 = 0;
    for (1..3) |i| {
        for (i..4) |j| {
            const first = i * keysize;
            const second = j * keysize;
            total_hamming_dist += hammingDistance(src[first .. first + keysize], src[second .. second + keysize]);
        }
    }
    const sum: f64 = @floatFromInt(total_hamming_dist);
    const norm_div: f64 = @floatFromInt(keysize);
    return sum / norm_div;
}

/// This function computes the normalized hamming distance
/// for a given keysize, take two chunks of the slice in
/// keysize blocks and then get the hamming distance between
/// them, then add up all of these chunks and divide by keysize
fn normalizedHammingDist(src: []u8, keysize: u64) f64 {
    assert(keysize * 2 < src.len);
    var sum: u64 = 0;
    const first: usize = 0;
    var second = keysize;
    var num_blocks: f64 = 0.0;
    while (second + keysize < src.len) {
        const first_chunk = src[first .. first + keysize];
        const second_chunk = src[second .. second + keysize];
        sum += hammingDistance(first_chunk, second_chunk);
        second += keysize;
        num_blocks += 1;
    }
    const top: f64 = @floatFromInt(sum);
    const bot: f64 = @floatFromInt(keysize);
    return (top / bot) / num_blocks;
}

const MAXKEYSIZE = 40;

/// Given a specific column of a row major slice
/// stored in src, copy the bytes to dst for a specific
/// column
fn copyColumn(src: []const u8, dst: []u8, col: usize, num_rows: usize, row_length: usize) void {
    // TODO add asserts
    for (0..num_rows) |row| {
        const idx = col + row_length * row;
        if (src.len <= idx) {
            break;
        }
        dst[row] = src[idx];
    }
}

pub fn breakRepeatingKeyXor(ciphertext: []u8) ![]u8 {
    const Entry = struct {
        keysize: u64,
        score: f64,
    };
    var best_keysize: Entry = .{ .keysize = std.math.maxInt(u64), .score = std.math.floatMax(f64) };
    for (2..MAXKEYSIZE) |keysize| {
        const score = normalizedHammingDist(ciphertext, keysize);
        if (score < best_keysize.score) {
            best_keysize = .{ .keysize = @as(u64, keysize), .score = score };
        }
    }
    const keysize: u64 = best_keysize.keysize;
    const key: []u8 = try alloc.alloc(u8, keysize);
    const col_len = (ciphertext.len / keysize) + 1;

    for (0..keysize) |col| {
        const col_buf = try alloc.alloc(u8, col_len);
        defer alloc.free(col_buf);
        copyColumn(ciphertext, col_buf, col, col_len, keysize);
        const single_key = try single_byte_key(col_buf);
        key[col] = single_key;
    }
    return key;
}

/// returns the decrypted code
pub fn aes_ecb_decrypt(key: [16]u8, encrypted: []u8) ![]u8 {
    var decrypt_ctx = aes.Aes128.initDec(key);

    var src: [16]u8 = undefined;
    var dst: [16]u8 = undefined;

    var i: usize = 0;
    while (i < 16) : (i += 1) {
        src[i] = 0;
    }
    const decrypted = try alloc.alloc(u8, encrypted.len);
    var block_iter = std.mem.window(u8, encrypted, 16, 16);
    var block_idx: usize = 0;
    while (block_iter.next()) |block| {
        for (block, 0..) |b, j| {
            src[j] = b;
        }
        decrypt_ctx.decrypt(&dst, &src);

        var j: usize = 0;
        while (j < 16 and block_idx * 16 + j < decrypted.len) : (j += 1) {
            decrypted[block_idx * 16 + j] = dst[j];
        }
        block_idx += 1;
    }
    return decrypted;
}

test "set 1 challenge 1" {
    const given_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    const calculated = try hex_to_base64(given_hex);
    try std.testing.expectEqualStrings(expected, calculated);
}

test "set 1 challenge 2" {
    const hex1_str = "1c0111001f010100061a024b53535009181c";
    const hex2_str = "686974207468652062756c6c277320657965";
    const hex1_bytes = try alloc.alloc(u8, hex1_str.len);
    const hex1 = try fmt.hexToBytes(hex1_bytes, hex1_str);
    const hex2_bytes = try alloc.alloc(u8, hex2_str.len);
    const hex2 = try fmt.hexToBytes(hex2_bytes, hex2_str);
    const xor_result = try fixed_xor(hex1, hex2);
    const expected_res = "746865206b696420646f6e277420706c6179";
    const expected_bytes = try alloc.alloc(u8, expected_res.len);
    const expected = try fmt.hexToBytes(expected_bytes, expected_res);
    try std.testing.expectEqualSlices(u8, expected, xor_result);
}

test "set 1 challenge 5" {
    const plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const key = "ICE";
    const ciphertext = try repeating_key_xor(key, plaintext);
    var cipher: [200]u8 = undefined;
    _ = try std.fmt.bufPrint(&cipher, "{}", .{std.fmt.fmtSliceHexLower(ciphertext)});
    const expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    try std.testing.expectEqualSlices(u8, expected, cipher[0..expected.len]);
}

test "Hamming Distance" {
    const b1 = "this is a test";
    const b2 = "wokka wokka!!!";
    const dist = hammingDistance(b1, b2);
    const expected = 37;
    try expect(dist == expected);
}

test "Turn lowerCase" {
    const b1 = 'a';
    const b2 = 'A';
    const b3 = 0x20;
    assert(turnLowercase(b1) == 'a');
    assert(turnLowercase(b2) == 'a');
    assert(turnLowercase(b3) == 0x20);
}
