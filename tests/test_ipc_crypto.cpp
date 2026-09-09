#include "../src/ipc_crypto.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <type_traits>

using namespace alfie;

static void test_keypairs_are_move_only_and_public_keys_are_x25519_size() {
    static_assert(!std::is_copy_constructible_v<IpcKeyPair>);
    static_assert(!std::is_copy_assignable_v<IpcKeyPair>);

    auto server = generate_ipc_keypair();
    auto client = generate_ipc_keypair();
    assert(server.public_key.size() == 32);
    assert(client.public_key.size() == 32);
    assert(server.private_key.size() == 32);
    assert(client.private_key.size() == 32);
}

static void test_x25519_hkdf_session_key_matches_on_both_sides() {
    auto server = generate_ipc_keypair();
    auto client = generate_ipc_keypair();
    IpcRequestContext ctx{"one-time-token", "example.com", "fill_password"};

    auto server_key = derive_ipc_session_key(server.private_key, client.public_key, ctx);
    auto client_key = derive_ipc_session_key(client.private_key, server.public_key, ctx);

    assert(server_key.size() == 32);
    assert(server_key.str() == client_key.str());
}

static void test_ipc_encrypts_secret_and_decrypts_once() {
    auto server = generate_ipc_keypair();
    auto client = generate_ipc_keypair();
    IpcRequestContext ctx{"one-time-token", "example.com", "fill_password"};
    auto sender_key = derive_ipc_session_key(server.private_key, client.public_key, ctx);
    auto receiver_key = derive_ipc_session_key(client.private_key, server.public_key, ctx);
    SecureBuffer secret(R"({"secret":"VERY-SECRET-IPC"})");

    auto frame = encrypt_ipc_message(sender_key, ctx, secret);
    std::string raw(frame.ciphertext_and_tag.begin(), frame.ciphertext_and_tag.end());
    assert(raw.find("VERY-SECRET-IPC") == std::string::npos);

    ReplayGuard guard;
    auto decrypted = decrypt_ipc_message(receiver_key, ctx, frame, guard);
    assert(decrypted.str() == R"({"secret":"VERY-SECRET-IPC"})");

    bool replay_rejected = false;
    try {
        (void)decrypt_ipc_message(receiver_key, ctx, frame, guard);
    } catch (const CryptoError&) {
        replay_rejected = true;
    }
    assert(replay_rejected);
}

static void test_ipc_aad_binds_token_domain_and_action() {
    auto server = generate_ipc_keypair();
    auto client = generate_ipc_keypair();
    IpcRequestContext ctx{"token-a", "example.com", "fill_password"};
    auto sender_key = derive_ipc_session_key(server.private_key, client.public_key, ctx);
    auto receiver_key = derive_ipc_session_key(client.private_key, server.public_key, ctx);
    SecureBuffer secret("secret");
    auto frame = encrypt_ipc_message(sender_key, ctx, secret);

    ReplayGuard guard;
    bool failed = false;
    try {
        IpcRequestContext tampered{"token-a", "evil.example", "fill_password"};
        (void)decrypt_ipc_message(receiver_key, tampered, frame, guard);
    } catch (const CryptoError&) {
        failed = true;
    }
    assert(failed);
}

int main() {
    test_keypairs_are_move_only_and_public_keys_are_x25519_size();
    test_x25519_hkdf_session_key_matches_on_both_sides();
    test_ipc_encrypts_secret_and_decrypts_once();
    test_ipc_aad_binds_token_domain_and_action();
    std::cout << "IPC crypto tests passed\n";
}
