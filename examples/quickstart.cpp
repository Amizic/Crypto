// Crypto - examples/quickstart.cpp
//
// The smallest useful tour of the library: AES-256-GCM, RSA-4096 and
// ML-KEM-768 (post-quantum), plus the helpers that tie them together (HKDF,
// SHA-256 and the PostQuantum hybrid envelope).
//
// Everything is a plain int return: 0 = ok, negative = kErr* code.

#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "Crypto.hpp"

namespace {

std::vector<uint8_t> bytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

// --- 1. Aes256: one key, one fresh IV per message ---------------------------
void aesDemo() {
    std::cout << "--- AES-256-GCM ---\n";
    Crypto::Aes256 aes;

    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    if (aes.generateKey(key) != 0 || aes.generateIv(iv) != 0) {
        return;
    }

    const std::vector<uint8_t> message = bytes("hello from AES");
    std::vector<uint8_t> cipher;
    std::array<uint8_t, 16> tag{};
    if (aes.encrypt(message, key, iv, cipher, tag) != 0) {
        return;
    }

    // Receiver: same key (shared once), IV + ciphertext + tag from the wire.
    std::vector<uint8_t> plain;
    if (aes.decrypt(cipher, key, iv,
                    std::vector<uint8_t>(tag.begin(), tag.end()), plain) != 0 ||
        plain != message) {
        std::cout << "  AES failed\n";
        return;
    }
    std::cout << "  round trip ok (" << cipher.size() << " ciphertext bytes)\n";
}

// --- 2. Rsa4096: sign/verify + small OAEP messages + key transfer -----------
void rsaDemo() {
    std::cout << "--- RSA-4096 ---\n";
    Crypto::Rsa4096 rsa;

    EVP_PKEY* raw = nullptr;
    if (rsa.generateKeyPair(&raw) != 0) {
        return;
    }
    Crypto::EvpPkeyPtr key = Crypto::wrapPkey(raw);

    // Sign with the private key, verify with the public key.
    Crypto::Sha256 sha;
    std::vector<uint8_t> digest;
    std::vector<uint8_t> signature;
    const std::vector<uint8_t> message = bytes("signed command");
    if (sha.hash(message, digest) != 0 ||
        rsa.sign(key.get(), digest, signature) != 0 ||
        rsa.verify(key.get(), digest, signature) != 0) {
        std::cout << "  RSA signature failed\n";
        return;
    }
    std::cout << "  signature ok (" << signature.size() << " bytes)\n";

    // Give the PUBLIC key to the other side as a PEM string...
    std::string pem;
    if (rsa.savePublicKeyPem(key.get(), pem) != 0) {
        return;
    }
    // ...the other side loads it and verifies with it.
    EVP_PKEY* rawPeer = nullptr;
    if (rsa.loadPublicKeyPem(pem, &rawPeer) != 0) {
        return;
    }
    Crypto::EvpPkeyPtr peerKey = Crypto::wrapPkey(rawPeer);
    if (rsa.verify(peerKey.get(), digest, signature) != 0) {
        std::cout << "  verify with transferred key failed\n";
        return;
    }
    std::cout << "  verify with transferred public key ok\n";

    // RSA-OAEP encryption (max 446 bytes per call -> wrap keys, not files).
    std::vector<uint8_t> cipher;
    std::vector<uint8_t> plain;
    const std::vector<uint8_t> payload = bytes("small RSA payload");
    if (rsa.encrypt(peerKey.get(), payload, cipher) != 0 ||
        rsa.decrypt(key.get(), cipher, plain) != 0 || plain != payload) {
        std::cout << "  RSA encryption failed\n";
        return;
    }
    std::cout << "  OAEP round trip ok\n";
}

// --- 3. MlKem768 (post-quantum) + what to do with the shared secret ---------
void mlKemDemo() {
    std::cout << "--- ML-KEM-768 (post-quantum) ---\n";
    Crypto::MlKem768 kem;

    // Alice: make a keypair, send the public key to Bob.
    std::vector<uint8_t> alicePub;
    std::vector<uint8_t> aliceSec;
    if (kem.generateKeyPair(alicePub, aliceSec) != 0) {
        return;
    }

    // Bob: encapsulate a fresh secret to Alice's public key, send her the
    // ciphertext.
    std::vector<uint8_t> ct;
    std::vector<uint8_t> bobSecret;
    if (kem.encapsulate(alicePub, ct, bobSecret) != 0) {
        return;
    }

    // Alice: decapsulate -> the SAME 32-byte secret as Bob's.
    std::vector<uint8_t> aliceSecret;
    if (kem.decapsulate(ct, aliceSec, aliceSecret) != 0) {
        return;
    }
    if (aliceSecret != bobSecret) {
        std::cout << "  shared secrets differ\n";
        return;
    }
    std::cout << "  both sides derived the same 32-byte secret\n";

    // Derive a dedicated AES key from the shared secret (optional salt/info).
    Crypto::Hkdf hkdf;
    std::vector<uint8_t> aesKey;
    if (hkdf.derive(aliceSecret, std::vector<uint8_t>(),
                    std::vector<uint8_t>(), 32, aesKey) != 0) {
        return;
    }
    std::cout << "  HKDF derived an AES key (" << aesKey.size() << " bytes)\n";

    // OR skip the manual steps: one-call PostQuantum hybrid encryption.
    Crypto::PostQuantum pq;
    std::vector<uint8_t> envelope;
    std::vector<uint8_t> opened;
    const std::vector<uint8_t> message = bytes("post-quantum message");
    if (pq.encrypt(alicePub, message, envelope) != 0 ||
        pq.decrypt(aliceSec, envelope, opened) != 0 || opened != message) {
        std::cout << "  hybrid round trip failed\n";
        return;
    }
    std::cout << "  hybrid envelope round trip ok (" << envelope.size()
              << " envelope bytes)\n";
}

// --- 4. A realistic session: handshake once, then 5 messages ----------------
void fiveMessagesDemo() {
    std::cout << "--- A session: handshake + 5 messages ---\n";

    Crypto::MlKem768 kem;
    Crypto::Hkdf hkdf;
    Crypto::Aes256 aes;

    // ---- one-time handshake ------------------------------------------------
    // Client: keypair; public key -> wire -> server.
    std::vector<uint8_t> clientPub;
    std::vector<uint8_t> clientSec;
    if (kem.generateKeyPair(clientPub, clientSec) != 0) {
        return;
    }
    // Server: encapsulate; ciphertext -> wire -> client.
    std::vector<uint8_t> ct;
    std::vector<uint8_t> serverShared;
    if (kem.encapsulate(clientPub, ct, serverShared) != 0) {
        return;
    }
    // Client: decapsulate -> the same secret.
    std::vector<uint8_t> clientShared;
    if (kem.decapsulate(ct, clientSec, clientShared) != 0) {
        return;
    }
    if (clientShared != serverShared) {
        std::cout << "  handshake failed\n";
        return;
    }
    std::cout << "  handshake: both sides hold the same 32-byte secret\n";

    // ---- derive one AES key per direction (best practice) ------------------
    std::vector<uint8_t> clientToServerKey;
    std::vector<uint8_t> serverToClientKey;
    if (hkdf.derive(clientShared, std::vector<uint8_t>(),
                    bytes("client->server"), 32, clientToServerKey) != 0 ||
        hkdf.derive(clientShared, std::vector<uint8_t>(),
                    bytes("server->client"), 32, serverToClientKey) != 0) {
        return;
    }
    std::cout << "  derived separate AES keys for each direction\n";

    // ---- client sends 5 messages -------------------------------------------
    for (int i = 1; i <= 5; ++i) {
        const std::vector<uint8_t> message = bytes("message #" + std::to_string(i));

        // Sender: fresh IV, encrypt, then lay the message out for the wire.
        std::vector<uint8_t> iv;
        std::vector<uint8_t> cipher;
        std::array<uint8_t, 16> tag{};
        if (aes.generateIv(iv) != 0 ||
            aes.encrypt(message, clientToServerKey, iv, cipher, tag) != 0) {
            return;
        }
        // Wire layout: [12-byte IV][ciphertext][16-byte tag].
        // (A real socket also prepends a length prefix; the crypto part is
        //  exactly this.)
        std::vector<uint8_t> wire;
        wire.insert(wire.end(), iv.begin(), iv.end());
        wire.insert(wire.end(), cipher.begin(), cipher.end());
        wire.insert(wire.end(), tag.begin(), tag.end());

        // Receiver: split the blob back and decrypt with the SAME key.
        const std::vector<uint8_t> rxIv(wire.begin(),
                                         wire.begin() + Crypto::Aes256::kIvSize);
        const std::vector<uint8_t> rxTag(wire.end() - Crypto::Aes256::kTagSize,
                                         wire.end());
        const std::vector<uint8_t> rxCipher(
            wire.begin() + Crypto::Aes256::kIvSize,
            wire.end() - Crypto::Aes256::kTagSize);
        std::vector<uint8_t> plain;
        if (aes.decrypt(rxCipher, clientToServerKey, rxIv, rxTag, plain) != 0 ||
            plain != message) {
            std::cout << "  message #" << i << " failed\n";
            return;
        }
        std::cout << "  msg " << i << "/5: " << wire.size()
                  << " bytes on the wire, decrypted ok\n";
    }
}

} // namespace

int main() {
    aesDemo();
    rsaDemo();
    mlKemDemo();
    fiveMessagesDemo();
    std::cout << "done\n";
    return 0;
}
