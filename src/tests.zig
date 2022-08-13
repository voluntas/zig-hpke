const std = @import("std");
const hpke = @import("main.zig");
const fmt = std.fmt;
const testing = std.testing;
const primitives = hpke.primitives;
const max_aead_tag_length = hpke.max_aead_tag_length;
const Suite = hpke.Suite;

test "hpke" {
    const suite = try Suite.init(
        primitives.Kem.X25519HkdfSha256.id,
        primitives.Kdf.HkdfSha256.id,
        primitives.Aead.Aes128Gcm.id,
    );

    var info_hex = "4f6465206f6e2061204772656369616e2055726e";
    var info: [info_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&info, info_hex);

    const server_seed_hex = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037";
    var server_seed: [server_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&server_seed, server_seed_hex);
    var server_kp = try suite.deriveKeyPair(&server_seed);

    var expected: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    try testing.expectEqualSlices(u8, &expected, server_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    try testing.expectEqualSlices(u8, &expected, server_kp.public_key.slice());

    const client_seed_hex = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
    var client_seed: [client_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&client_seed, client_seed_hex);
    var client_kp = try suite.deriveKeyPair(&client_seed);
    _ = client_kp;

    var client_ctx_and_encapsulated_secret = try suite.createClientContext(server_kp.public_key.slice(), &info, null, &client_seed);
    var encapsulated_secret = client_ctx_and_encapsulated_secret.encapsulated_secret;
    _ = try fmt.hexToBytes(&expected, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    try testing.expectEqualSlices(u8, &expected, encapsulated_secret.encapsulated.constSlice());
    _ = try fmt.hexToBytes(&expected, "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
    try testing.expectEqualSlices(u8, &expected, encapsulated_secret.secret.constSlice());

    var client_ctx = client_ctx_and_encapsulated_secret.client_ctx;

    var key = client_ctx.ctx.outbound_state.?.key;
    _ = try fmt.hexToBytes(&expected, "4531685d41d65f03dc48f6b8302c05b0");
    try testing.expectEqualSlices(u8, expected[0..key.len], key.constSlice());

    var base_nonce = client_ctx.ctx.outbound_state.?.base_nonce;
    _ = try fmt.hexToBytes(&expected, "56d890e5accaaf011cff4b7d");
    try testing.expectEqualSlices(u8, expected[0..base_nonce.len], base_nonce.constSlice());

    // var counter = client_ctx.ctx.outbound_state.?.counter;
    // std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(counter.constSlice())});

    var server_ctx = try suite.createServerContext(encapsulated_secret.encapsulated.constSlice(), server_kp, &info, null);

    // sequence number: 0
    // pt: 4265617574792069732074727574682c20747275746820626561757479
    // aad: 436f756e742d30
    // nonce: 56d890e5accaaf011cff4b7d
    // ct: f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9
    // 6d8770ac83d07bea87e13c512a
    var message: [29]u8 = undefined;
    _ = try fmt.hexToBytes(&message, "4265617574792069732074727574682c20747275746820626561757479");
    var ad: [7]u8 = undefined;
    _ = try fmt.hexToBytes(&ad, "436f756e742d30");
    var ciphertext: [max_aead_tag_length + message.len]u8 = undefined;
    client_ctx.encryptToServer(&ciphertext, &message, &ad);
    var ct: [45]u8 = undefined;
    _ = try fmt.hexToBytes(&ct, "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");
    try testing.expectEqualSlices(u8, &ct, &ciphertext);

    var message2: [29]u8 = undefined;
    try server_ctx.decryptFromClient(&message2, &ciphertext, &ad);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);

    // sequence number: 1
    // pt: 4265617574792069732074727574682c20747275746820626561757479
    // aad: 436f756e742d31
    // nonce: 56d890e5accaaf011cff4b7c
    // ct: af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab25
    // 1c03d0c22a56b8ca42c2063b84
    _ = try fmt.hexToBytes(&message, "4265617574792069732074727574682c20747275746820626561757479");
    _ = try fmt.hexToBytes(&ad, "436f756e742d31");
    client_ctx.encryptToServer(&ciphertext, &message, &ad);
    _ = try fmt.hexToBytes(&ct, "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84");
    try testing.expectEqualSlices(u8, &ct, &ciphertext);

    try server_ctx.decryptFromClient(&message2, &ciphertext, &ad);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);

    // sequence number: 2
    // pt: 4265617574792069732074727574682c20747275746820626561757479
    // aad: 436f756e742d32
    // nonce: 56d890e5accaaf011cff4b7f
    // ct: 498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb7251649158
    // 8d96a19ad4a683518973dcc180
    _ = try fmt.hexToBytes(&message, "4265617574792069732074727574682c20747275746820626561757479");
    _ = try fmt.hexToBytes(&ad, "436f756e742d32");
    client_ctx.encryptToServer(&ciphertext, &message, &ad);
    _ = try fmt.hexToBytes(&ct, "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180");
    try testing.expectEqualSlices(u8, &ct, &ciphertext);
    
    try server_ctx.decryptFromClient(&message2, &ciphertext, &ad);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);
    
    // skip
    client_ctx.encryptToServer(&ciphertext, &message, &ad);

    try server_ctx.decryptFromClient(&message2, &ciphertext, &ad);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);

    // sequence number: 4
    // pt: 4265617574792069732074727574682c20747275746820626561757479
    // aad: 436f756e742d34
    // nonce: 56d890e5accaaf011cff4b79
    // ct: 583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a
    // 09fc0012bc69fccaa251c0246d
    _ = try fmt.hexToBytes(&message, "4265617574792069732074727574682c20747275746820626561757479");
    _ = try fmt.hexToBytes(&ad, "436f756e742d34");
    client_ctx.encryptToServer(&ciphertext, &message, &ad);
    _ = try fmt.hexToBytes(&ct, "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d");
    try testing.expectEqualSlices(u8, &ct, &ciphertext);

    try server_ctx.decryptFromClient(&message2, &ciphertext, &ad);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);

    var end: u32 = 254;
    var i: u32 = 4;
    while (i < end): (i += 1) {
        client_ctx.encryptToServer(&ciphertext, &message, &ad);
        try server_ctx.decryptFromClient(&message2, &ciphertext, &ad);
        try testing.expectEqualSlices(u8, message[0..], message2[0..]);
    }

    // var counter = client_ctx.ctx.outbound_state.?.counter;
    // std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(counter.constSlice())});

    // sequence number: 255
    // pt: 4265617574792069732074727574682c20747275746820626561757479
    // aad: 436f756e742d323535
    // nonce: 56d890e5accaaf011cff4b82
    // ct: 7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505b
    // f106deefec4a49ac38d71c9e0a
    _ = try fmt.hexToBytes(&message, "4265617574792069732074727574682c20747275746820626561757479");
    var ad2: [9]u8 = undefined;
    _ = try fmt.hexToBytes(&ad2, "436f756e742d323535");
    client_ctx.encryptToServer(&ciphertext, &message, &ad2);
    _ = try fmt.hexToBytes(&ct, "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a");
    try testing.expectEqualSlices(u8, &ct, &ciphertext);

    try server_ctx.decryptFromClient(&message2, &ciphertext, &ad2);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);

    // sequence number: 256
    // pt: 4265617574792069732074727574682c20747275746820626561757479
    // aad: 436f756e742d323536
    // nonce: 56d890e5accaaf011cff4a7d
    // ct: 957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3
    // fbeda97d2e0e1aba483a2df9f2
    _ = try fmt.hexToBytes(&message, "4265617574792069732074727574682c20747275746820626561757479");
    _ = try fmt.hexToBytes(&ad2, "436f756e742d323536");
    client_ctx.encryptToServer(&ciphertext, &message, &ad2);
    _ = try fmt.hexToBytes(&ct, "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2");
    try testing.expectEqualSlices(u8, &ct, &ciphertext);

    try server_ctx.decryptFromClient(&message2, &ciphertext, &ad2);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);

    // std.debug.print("{}\n", .{ciphertext.len});
    // std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(&ciphertext)});

    // _ = try fmt.hexToBytes(&expected, "56d890e5accaaf011cff4b7d");
    // const base_nonce = client_ctx.ctx.outbound_state.?.base_nonce.constSlice();
    // try testing.expectEqualSlices(u8, base_nonce, expected[0..base_nonce.len]);

    // exporter_context:
    // L: 32
    // exported_value:
    // 3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee
    var exported_secret: [expected.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee");
    try client_ctx.exportSecret(&exported_secret, "");
    // std.debug.print("client_ctx: {s}\n", .{std.fmt.fmtSliceHexLower(&exported_secret)});
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, "");
    // std.debug.print("server_ctx: {s}\n", .{std.fmt.fmtSliceHexLower(&exported_secret)});
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    // exporter_context: 00
    // L: 32
    // exported_value:
    // 2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5
    _ = try fmt.hexToBytes(&expected, "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5");
    
    _ = try fmt.hexToBytes(&expected, "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5");
    var exporter_context: [1]u8 = undefined;
    _ = try fmt.hexToBytes(&exporter_context, "00");
    try client_ctx.exportSecret(&exported_secret, &exporter_context);
    // std.debug.print("client_ctx: {s}\n", .{std.fmt.fmtSliceHexLower(&exported_secret)});
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, &exporter_context);
    // std.debug.print("server_ctx: {s}\n", .{std.fmt.fmtSliceHexLower(&exported_secret)});
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    // exporter_context: 54657374436f6e74657874
    // L: 32
    // exported_value:
    // e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931
    _ = try fmt.hexToBytes(&expected, "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931");
    var exporter_context2: [11]u8 = undefined;
    _ = try fmt.hexToBytes(&exporter_context2, "54657374436f6e74657874");
    try client_ctx.exportSecret(&exported_secret, &exporter_context2);
    // std.debug.print("client_ctx: {s}\n", .{std.fmt.fmtSliceHexLower(&exported_secret)});
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, &exporter_context2);
    // std.debug.print("server_ctx: {s}\n", .{std.fmt.fmtSliceHexLower(&exported_secret)});
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    // client_ctx_and_encapsulated_secret = try suite.createAuthenticatedClientContext(
    //     client_kp,
    //     server_kp.public_key.constSlice(),
    //     &info,
    //     null,
    //     null,
    // );
    // encapsulated_secret = client_ctx_and_encapsulated_secret.encapsulated_secret;
    // client_ctx = client_ctx_and_encapsulated_secret.client_ctx;
    // server_ctx = try suite.createAuthenticatedServerContext(
    //     client_kp.public_key.constSlice(),
    //     encapsulated_secret.encapsulated.constSlice(),
    //     server_kp,
    //     &info,
    //     null,
    // );
    // client_ctx.encryptToServer(&ciphertext, message, ad);
    // try server_ctx.decryptFromClient(&message2, &ciphertext, ad);
    // try testing.expectEqualSlices(u8, message[0..], message2[0..]);

    // server_ctx.encryptToClient(&ciphertext, message, ad);
    // try client_ctx.decryptFromServer(&message2, &ciphertext, ad);
    // try testing.expectEqualSlices(u8, message[0..], message2[0..]);
}
