const std = @import("std");
const hpke = @import("main.zig");
const fmt = std.fmt;
const testing = std.testing;
const primitives = hpke.primitives;
const max_aead_tag_length = hpke.max_aead_tag_length;
const Suite = hpke.Suite;

// https://www.rfc-editor.org/rfc/rfc9180.html#name-dhkemx25519-hkdf-sha256-hkd

// https://www.rfc-editor.org/rfc/rfc9180.html#name-base-setup-information
test "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM Base" {
    const suite = try Suite.init(
        primitives.Kem.X25519HkdfSha256.id,
        primitives.Kdf.HkdfSha256.id,
        primitives.Aead.Aes128Gcm.id,
    );

    var info_hex = "4f6465206f6e2061204772656369616e2055726e";
    var info: [info_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&info, info_hex);

    const ephemeral_seed_hex = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037";
    var ephemeral_seed: [ephemeral_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&ephemeral_seed, ephemeral_seed_hex);
    var ephemeral_kp = try suite.deriveKeyPair(&ephemeral_seed);

    var expected: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    try testing.expectEqualSlices(u8, &expected, ephemeral_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    try testing.expectEqualSlices(u8, &expected, ephemeral_kp.public_key.slice());

    const client_seed_hex = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
    var client_seed: [client_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&client_seed, client_seed_hex);
    var client_kp = try suite.deriveKeyPair(&client_seed);
    _ = client_kp;

    var client_ctx_and_encapsulated_secret = try suite.createClientContext(ephemeral_kp.public_key.slice(), &info, null, &client_seed);
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

    var server_ctx = try suite.createServerContext(encapsulated_secret.encapsulated.constSlice(), ephemeral_kp, &info, null);

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
    var exporter_context: [1]u8 = undefined;
    _ = try fmt.hexToBytes(&exporter_context, "00");

    _ = try fmt.hexToBytes(&expected, "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5");

    try client_ctx.exportSecret(&exported_secret, &exporter_context);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, &exporter_context);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    // exporter_context: 54657374436f6e74657874
    // L: 32
    // exported_value:
    // e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931
    var exporter_context2: [11]u8 = undefined;
    _ = try fmt.hexToBytes(&exporter_context2, "54657374436f6e74657874");

    _ = try fmt.hexToBytes(&expected, "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931");

    try client_ctx.exportSecret(&exported_secret, &exporter_context2);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, &exporter_context2);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);
}

// https://www.rfc-editor.org/rfc/rfc9180.html#name-psk-setup-information
test "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM PSK" {
    const suite = try Suite.init(
        primitives.Kem.X25519HkdfSha256.id,
        primitives.Kdf.HkdfSha256.id,
        primitives.Aead.Aes128Gcm.id,
    );

    var info_hex = "4f6465206f6e2061204772656369616e2055726e";
    var info: [info_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&info, info_hex);

    const ephemeral_seed_hex = "78628c354e46f3e169bd231be7b2ff1c77aa302460a26dbfa15515684c00130b";
    var ephemeral_seed: [ephemeral_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&ephemeral_seed, ephemeral_seed_hex);
    var ephemeral_kp = try suite.deriveKeyPair(&ephemeral_seed);

    var expected: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "463426a9ffb42bb17dbe6044b9abd1d4e4d95f9041cef0e99d7824eef2b6f588");
    try testing.expectEqualSlices(u8, &expected, ephemeral_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b");
    try testing.expectEqualSlices(u8, &expected, ephemeral_kp.public_key.slice());

    const server_seed_hex = "d4a09d09f575fef425905d2ab396c1449141463f698f8efdb7accfaff8995098";
    var server_seed: [server_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&server_seed, server_seed_hex);
    var server_kp = try suite.deriveKeyPair(&server_seed);

    _ = try fmt.hexToBytes(&expected, "c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd");
    try testing.expectEqualSlices(u8, &expected, server_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366");
    try testing.expectEqualSlices(u8, &expected, server_kp.public_key.slice());

    var psk_key: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&psk_key, "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    var psk_id: [22]u8 = undefined;
    _ = try fmt.hexToBytes(&psk_id, "456e6e796e20447572696e206172616e204d6f726961");

    var psk = hpke.Psk{
        .key = &psk_key,
        .id = &psk_id, 
    };
    _ = psk;

    var client_ctx_and_encapsulated_secret = try suite.createClientContext(server_kp.public_key.slice(), &info, psk, &ephemeral_seed);
    var encapsulated_secret = client_ctx_and_encapsulated_secret.encapsulated_secret;

    // enc:
    // 0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b
    _ = try fmt.hexToBytes(&expected, "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b");
    try testing.expectEqualSlices(u8, &expected, encapsulated_secret.encapsulated.constSlice());
    // shared_secret:
    // 727699f009ffe3c076315019c69648366b69171439bd7dd0807743bde76986cd
    _ = try fmt.hexToBytes(&expected, "727699f009ffe3c076315019c69648366b69171439bd7dd0807743bde76986cd");
    try testing.expectEqualSlices(u8, &expected, encapsulated_secret.secret.constSlice());

    var client_ctx = client_ctx_and_encapsulated_secret.client_ctx;
    _ = client_ctx;

    var key = client_ctx.ctx.outbound_state.?.key;
    _ = try fmt.hexToBytes(&expected, "15026dba546e3ae05836fc7de5a7bb26");
    try testing.expectEqualSlices(u8, expected[0..key.len], key.constSlice());

    var base_nonce = client_ctx.ctx.outbound_state.?.base_nonce;
    _ = try fmt.hexToBytes(&expected, "9518635eba129d5ce0914555");
    try testing.expectEqualSlices(u8, expected[0..base_nonce.len], base_nonce.constSlice());

    var exporter_secret = client_ctx.ctx.exporter_secret;
    _ = try fmt.hexToBytes(&expected, "3d76025dbbedc49448ec3f9080a1abab6b06e91c0b11ad23c912f043a0ee7655");
    try testing.expectEqualSlices(u8, expected[0..exporter_secret.len], exporter_secret.constSlice());
}

// https://www.rfc-editor.org/rfc/rfc9180.html#name-auth-setup-information
test "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM Auth" {
    const suite = try Suite.init(
        primitives.Kem.X25519HkdfSha256.id,
        primitives.Kdf.HkdfSha256.id,
        primitives.Aead.Aes128Gcm.id,
    );

    var info_hex = "4f6465206f6e2061204772656369616e2055726e";
    var info: [info_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&info, info_hex);

    const ephemeral_seed_hex = "6e6d8f200ea2fb20c30b003a8b4f433d2f4ed4c2658d5bc8ce2fef718059c9f7";
    var ephemeral_seed: [ephemeral_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&ephemeral_seed, ephemeral_seed_hex);
    var ephemeral_kp = try suite.deriveKeyPair(&ephemeral_seed);

    var expected: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "ff4442ef24fbc3c1ff86375b0be1e77e88a0de1e79b30896d73411c5ff4c3518");
    try testing.expectEqualSlices(u8, &expected, ephemeral_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76");
    try testing.expectEqualSlices(u8, &expected, ephemeral_kp.public_key.slice());

    const server_seed_hex = "f1d4a30a4cef8d6d4e3b016e6fd3799ea057db4f345472ed302a67ce1c20cdec";
    var server_seed: [server_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&server_seed, server_seed_hex);
    var server_kp = try suite.deriveKeyPair(&server_seed);

    _ = try fmt.hexToBytes(&expected, "fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e");
    try testing.expectEqualSlices(u8, &expected, server_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e");
    try testing.expectEqualSlices(u8, &expected, server_kp.public_key.slice());

    const client_seed_hex = "94b020ce91d73fca4649006c7e7329a67b40c55e9e93cc907d282bbbff386f58";
    var client_seed: [client_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&client_seed, client_seed_hex);
    var client_kp = try suite.deriveKeyPair(&client_seed);
    _ = try fmt.hexToBytes(&expected, "dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd");
    try testing.expectEqualSlices(u8, &expected, client_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b");
    try testing.expectEqualSlices(u8, &expected, client_kp.public_key.slice());

    var client_auth_ctx_and_encapsulated_secret = try suite.createAuthenticatedClientContext(client_kp, server_kp.public_key.slice(), &info, null, &ephemeral_seed);
    var encapsulated_secret = client_auth_ctx_and_encapsulated_secret.encapsulated_secret;

    // enc:
    // 23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76
    _ = try fmt.hexToBytes(&expected, "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76");
    try testing.expectEqualSlices(u8, &expected, encapsulated_secret.encapsulated.constSlice());
    // shared_secret:
    // 2d6db4cf719dc7293fcbf3fa64690708e44e2bebc81f84608677958c0d4448a7
    _ = try fmt.hexToBytes(&expected, "2d6db4cf719dc7293fcbf3fa64690708e44e2bebc81f84608677958c0d4448a7");
    try testing.expectEqualSlices(u8, &expected, encapsulated_secret.secret.constSlice());

    var client_ctx = client_auth_ctx_and_encapsulated_secret.client_ctx;
    _ = client_ctx;

    var key = client_ctx.ctx.outbound_state.?.key;
    _ = try fmt.hexToBytes(&expected, "b062cb2c4dd4bca0ad7c7a12bbc341e6");
    try testing.expectEqualSlices(u8, expected[0..key.len], key.constSlice());

    var base_nonce = client_ctx.ctx.outbound_state.?.base_nonce;
    _ = try fmt.hexToBytes(&expected, "a1bc314c1942ade7051ffed0");
    try testing.expectEqualSlices(u8, expected[0..base_nonce.len], base_nonce.constSlice());

    var exporter_secret = client_ctx.ctx.exporter_secret;
    _ = try fmt.hexToBytes(&expected, "ee1a093e6e1c393c162ea98fdf20560c75909653550540a2700511b65c88c6f1");
    try testing.expectEqualSlices(u8, expected[0..exporter_secret.len], exporter_secret.constSlice());

    var server_ctx = try suite.createAuthenticatedServerContext(client_kp.public_key.constSlice(), encapsulated_secret.encapsulated.constSlice(), server_kp, &info, null);

    // exporter_context:
    // L: 32
    // exported_value:
    // 28c70088017d70c896a8420f04702c5a321d9cbf0279fba899b59e51bac72c85
    var exported_secret: [expected.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "28c70088017d70c896a8420f04702c5a321d9cbf0279fba899b59e51bac72c85");

    try client_ctx.exportSecret(&exported_secret, "");
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, "");
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    // exporter_context: 00
    // L: 32
    // exported_value:
    // 25dfc004b0892be1888c3914977aa9c9bbaf2c7471708a49e1195af48a6f29ce
    var exporter_context: [1]u8 = undefined;
    _ = try fmt.hexToBytes(&exporter_context, "00");

    _ = try fmt.hexToBytes(&expected, "25dfc004b0892be1888c3914977aa9c9bbaf2c7471708a49e1195af48a6f29ce");

    try client_ctx.exportSecret(&exported_secret, &exporter_context);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, &exporter_context);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    // exporter_context: 54657374436f6e74657874
    // L: 32
    // exported_value:
    // 5a0131813abc9a522cad678eb6bafaabc43389934adb8097d23c5ff68059eb64
    var exporter_context2: [11]u8 = undefined;
    _ = try fmt.hexToBytes(&exporter_context2, "54657374436f6e74657874");

    _ = try fmt.hexToBytes(&expected, "5a0131813abc9a522cad678eb6bafaabc43389934adb8097d23c5ff68059eb64");

    try client_ctx.exportSecret(&exported_secret, &exporter_context2);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, &exporter_context2);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);
}

// https://www.rfc-editor.org/rfc/rfc9180.html#name-authpsk-setup-information
test "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM AuthPSK" {
    const suite = try Suite.init(
        primitives.Kem.X25519HkdfSha256.id,
        primitives.Kdf.HkdfSha256.id,
        primitives.Aead.Aes128Gcm.id,
    );

    var info_hex = "4f6465206f6e2061204772656369616e2055726e";
    var info: [info_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&info, info_hex);

    const ephemeral_seed_hex = "4303619085a20ebcf18edd22782952b8a7161e1dbae6e46e143a52a96127cf84";
    var ephemeral_seed: [ephemeral_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&ephemeral_seed, ephemeral_seed_hex);
    var ephemeral_kp = try suite.deriveKeyPair(&ephemeral_seed);

    var expected: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "14de82a5897b613616a00c39b87429df35bc2b426bcfd73febcb45e903490768");
    try testing.expectEqualSlices(u8, &expected, ephemeral_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c");
    try testing.expectEqualSlices(u8, &expected, ephemeral_kp.public_key.slice());

    const server_seed_hex = "4b16221f3b269a88e207270b5e1de28cb01f847841b344b8314d6a622fe5ee90";
    var server_seed: [server_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&server_seed, server_seed_hex);
    var server_kp = try suite.deriveKeyPair(&server_seed);

    _ = try fmt.hexToBytes(&expected, "cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423");
    try testing.expectEqualSlices(u8, &expected, server_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976");
    try testing.expectEqualSlices(u8, &expected, server_kp.public_key.slice());

    const client_seed_hex = "62f77dcf5df0dd7eac54eac9f654f426d4161ec850cc65c54f8b65d2e0b4e345";
    var client_seed: [client_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&client_seed, client_seed_hex);
    var client_kp = try suite.deriveKeyPair(&client_seed);
    _ = try fmt.hexToBytes(&expected, "fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4");
    try testing.expectEqualSlices(u8, &expected, client_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e");
    try testing.expectEqualSlices(u8, &expected, client_kp.public_key.slice());

    var psk_key: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&psk_key, "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    var psk_id: [22]u8 = undefined;
    _ = try fmt.hexToBytes(&psk_id, "456e6e796e20447572696e206172616e204d6f726961");

    var psk = hpke.Psk{
        .key = &psk_key,
        .id = &psk_id, 
    };
    _ = psk;

    var client_auth_ctx_and_encapsulated_secret = try suite.createAuthenticatedClientContext(client_kp, server_kp.public_key.slice(), &info, psk, &ephemeral_seed);
    var encapsulated_secret = client_auth_ctx_and_encapsulated_secret.encapsulated_secret;

    // enc:
    // 820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c
    _ = try fmt.hexToBytes(&expected, "820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c");
    try testing.expectEqualSlices(u8, &expected, encapsulated_secret.encapsulated.constSlice());
    // shared_secret:
    // f9d0e870aba28d04709b2680cb8185466c6a6ff1d6e9d1091d5bf5e10ce3a577
    _ = try fmt.hexToBytes(&expected, "f9d0e870aba28d04709b2680cb8185466c6a6ff1d6e9d1091d5bf5e10ce3a577");
    try testing.expectEqualSlices(u8, &expected, encapsulated_secret.secret.constSlice());

    var client_ctx = client_auth_ctx_and_encapsulated_secret.client_ctx;
    _ = client_ctx;

    var key = client_ctx.ctx.outbound_state.?.key;
    _ = try fmt.hexToBytes(&expected, "1364ead92c47aa7becfa95203037b19a");
    try testing.expectEqualSlices(u8, expected[0..key.len], key.constSlice());

    var base_nonce = client_ctx.ctx.outbound_state.?.base_nonce;
    _ = try fmt.hexToBytes(&expected, "99d8b5c54669807e9fc70df1");
    try testing.expectEqualSlices(u8, expected[0..base_nonce.len], base_nonce.constSlice());

    var exporter_secret = client_ctx.ctx.exporter_secret;
    _ = try fmt.hexToBytes(&expected, "f048d55eacbf60f9c6154bd4021774d1075ebf963c6adc71fa846f183ab2dde6");
    try testing.expectEqualSlices(u8, expected[0..exporter_secret.len], exporter_secret.constSlice());

    var server_ctx = try suite.createAuthenticatedServerContext(client_kp.public_key.constSlice(), encapsulated_secret.encapsulated.constSlice(), server_kp, &info, psk);

    // exporter_context:
    // L: 32
    // exported_value:
    // 08f7e20644bb9b8af54ad66d2067457c5f9fcb2a23d9f6cb4445c0797b330067
    var exported_secret: [expected.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "08f7e20644bb9b8af54ad66d2067457c5f9fcb2a23d9f6cb4445c0797b330067");

    try client_ctx.exportSecret(&exported_secret, "");
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, "");
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    // exporter_context: 00
    // L: 32
    // exported_value:
    // 52e51ff7d436557ced5265ff8b94ce69cf7583f49cdb374e6aad801fc063b010
    var exporter_context: [1]u8 = undefined;
    _ = try fmt.hexToBytes(&exporter_context, "00");

    _ = try fmt.hexToBytes(&expected, "52e51ff7d436557ced5265ff8b94ce69cf7583f49cdb374e6aad801fc063b010");

    try client_ctx.exportSecret(&exported_secret, &exporter_context);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, &exporter_context);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    // exporter_context: 54657374436f6e74657874
    // L: 32
    // exported_value:
    // a30c20370c026bbea4dca51cb63761695132d342bae33a6a11527d3e7679436d
    var exporter_context2: [11]u8 = undefined;
    _ = try fmt.hexToBytes(&exporter_context2, "54657374436f6e74657874");

    _ = try fmt.hexToBytes(&expected, "a30c20370c026bbea4dca51cb63761695132d342bae33a6a11527d3e7679436d");

    try client_ctx.exportSecret(&exported_secret, &exporter_context2);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    try server_ctx.exportSecret(&exported_secret, &exporter_context2);
    try testing.expectEqualSlices(u8, &expected, &exported_secret);
}


