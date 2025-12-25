#include "auth.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <random>
#include <sodium.h>
#include <sstream>

namespace sap::sync {

    // libsodium requires initialization before use. We use a static flag to
    // ensure it's only initialized once.
    static bool ensure_sodium_initialized() {
        static bool initialized = false;
        static bool init_stl::result = false;
        if (!initialized) {
            init_stl::result = (sodium_init() >= 0);
            initialized = true;
        }
        return init_stl::result;
    }

    std::string base64_encode(const void* data, usize size) {
        ensure_sodium_initialized();
        // Calculate output size (base64 is ~4/3 of input + padding + null)
        usize encodedLen = sodium_base64_encoded_len(size, sodium_base64_VARIANT_ORIGINAL);
        std::string encoded(encodedLen, '\0');
        sodium_bin2base64(encoded.data(), encodedLen, static_cast<const unsigned char*>(data), size, sodium_base64_VARIANT_ORIGINAL);
        // Remove null terminator
        while (!encoded.empty() && encoded.back() == '\0') {
            encoded.pop_back();
        }
        return encoded;
    }

    std::string base64_encode(const std::vector<u8>& data) { return base64_encode(data.data(), data.size()); }

    stl::result<std::vector<u8>> base64_decode(std::string_view encoded) {
        ensure_sodium_initialized();
        // Maximum decoded size is 3/4 of encoded
        std::vector<u8> decoded(encoded.size());
        size_t decodedLen = 0;
        int rc = sodium_base642bin(decoded.data(), decoded.size(), encoded.data(), encoded.size(), nullptr, &decodedLen, nullptr,
                                   sodium_base64_VARIANT_ORIGINAL);
        if (rc != 0) {
            return stl::make_error<std::vector<u8>>("Invalid base64 encoding");
        }
        decoded.resize(decodedLen);
        return decoded;
    }

    // SSH public key format: "algorithm base64-data comment"
    // Example: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@hostname"
    // The base64 data itself contains:
    //   - 4 bytes: length of algorithm name (big-endian)
    //   - N bytes: algorithm name ("ssh-ed25519")
    //   - 4 bytes: length of key data (big-endian)
    //   - M bytes: raw key bytes (32 bytes for Ed25519)

    // Read a 4-byte big-endian length from buffer
    static u32 read_be32(const u8* data) {
        return (static_cast<u32>(data[0]) << 24) | (static_cast<u32>(data[1]) << 16) | (static_cast<u32>(data[2]) << 8) |
            (static_cast<u32>(data[3]));
    }

    std::string PublicKey::to_string() const {
        // Reconstruct the SSH format
        std::vector<u8> blob;
        // Algorithm length (big-endian)
        u32 algoLen = static_cast<u32>(algorithm.size());
        blob.push_back((algoLen >> 24) & 0xFF);
        blob.push_back((algoLen >> 16) & 0xFF);
        blob.push_back((algoLen >> 8) & 0xFF);
        blob.push_back(algoLen & 0xFF);
        // Algorithm
        blob.insert(blob.end(), algorithm.begin(), algorithm.end());
        // Key length (big-endian)
        u32 keyLen = static_cast<u32>(keyData.size());
        blob.push_back((keyLen >> 24) & 0xFF);
        blob.push_back((keyLen >> 16) & 0xFF);
        blob.push_back((keyLen >> 8) & 0xFF);
        blob.push_back(keyLen & 0xFF);
        // Key data
        blob.insert(blob.end(), keyData.begin(), keyData.end());
        std::string stl::result = algorithm + " " + base64_encode(blob);
        if (!comment.empty()) {
            stl::result += " " + comment;
        }
        return stl::result;
    }

    stl::result<PublicKey> parse_public_key(std::string_view keyString) {
        // Split by spaces: algorithm base64 [comment]
        std::istringstream iss(std::string(keyString));
        std::string algorithm, base64Data, comment;
        iss >> algorithm >> base64Data;
        std::getline(iss, comment);
        // Trim leading space from comment
        if (!comment.empty() && comment[0] == ' ') {
            comment = comment.substr(1);
        }
        if (algorithm.empty() || base64Data.empty()) {
            return stl::make_error<PublicKey>("Invalid SSH key format");
        }
        // We only support Ed25519
        if (algorithm != "ssh-ed25519") {
            return stl::make_error<PublicKey>("Unsupported key algorithm: " + algorithm + " (only ssh-ed25519 is supported)");
        }
        // Decode base64
        auto blobstl::result = base64_decode(base64Data);
        if (!blobstl::result) {
            return stl::make_error<PublicKey>("Invalid base64 in SSH key");
        }
        auto& blob = blobstl::result.value();
        // Parse the blob
        usize offset = 0;
        // Read algorithm name length
        if (offset + 4 > blob.size()) {
            return stl::make_error<PublicKey>("SSH key blob too short");
        }
        u32 algoLen = read_be32(&blob[offset]);
        offset += 4;
        // Read algorithm name
        if (offset + algoLen > blob.size()) {
            return stl::make_error<PublicKey>("SSH key blob truncated (algorithm)");
        }
        std::string blobAlgo(blob.begin() + offset, blob.begin() + offset + algoLen);
        offset += algoLen;
        if (blobAlgo != algorithm) {
            return stl::make_error<PublicKey>("Algorithm mismatch in SSH key");
        }
        // Read key data length
        if (offset + 4 > blob.size()) {
            return stl::make_error<PublicKey>("SSH key blob truncated (key length)");
        }
        u32 keyLen = read_be32(&blob[offset]);
        offset += 4;
        // Ed25519 public keys are exactly 32 bytes
        if (keyLen != crypto_sign_ed25519_PUBLICKEYBYTES) {
            return stl::make_error<PublicKey>("Invalid Ed25519 key length: " + std::to_string(keyLen));
        }
        // Read key data
        if (offset + keyLen > blob.size()) {
            return stl::make_error<PublicKey>("SSH key blob truncated (key data)");
        }
        PublicKey pk;
        pk.algorithm = algorithm;
        pk.keyData = std::vector<u8>(blob.begin() + offset, blob.begin() + offset + keyLen);
        pk.comment = comment;
        return pk;
    }

    // We generate cryptographically secure random bytes for the challenge.
    // This ensures each authentication attempt is unique (prevents replay attacks).
    std::string generate_challenge() {
        ensure_sodium_initialized();
        std::vector<u8> challenge(CHALLENGE_SIZE);
        randombytes_buf(challenge.data(), challenge.size());
        return base64_encode(challenge);
    }

    std::string generate_token() {
        ensure_sodium_initialized();
        // 32 bytes = 256 bits of randomness
        std::vector<u8> tokenBytes(32);
        randombytes_buf(tokenBytes.data(), tokenBytes.size());
        return base64_encode(tokenBytes);
    }

    // Ed25519 signature verification:
    // 1. Decode the signature from base64 (64 bytes)
    // 2. Decode the challenge from base64 (original random bytes)
    // 3. Use libsodium's crypto_sign_ed25519_verify_detached
    // The signature proves the signer has the private key corresponding to
    // the public key, without revealing the private key.
    stl::result<bool> verify_signature(const PublicKey& publicKey, std::string_view challenge, std::string_view signature) {
        ensure_sodium_initialized();
        // Verify key is Ed25519
        if (publicKey.algorithm != "ssh-ed25519") {
            return stl::make_error<bool>("Only Ed25519 keys are supported");
        }
        if (publicKey.keyData.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
            return stl::make_error<bool>("Invalid Ed25519 public key size");
        }
        // Decode challenge
        auto challengestl::result = base64_decode(challenge);
        if (!challengestl::result) {
            return stl::make_error<bool>("Invalid challenge encoding");
        }
        auto& challengeBytes = challengestl::result.value();
        // Decode signature
        auto sigstl::result = base64_decode(signature);
        if (!sigstl::result) {
            return stl::make_error<bool>("Invalid signature encoding");
        }
        auto& sigBytes = sigstl::result.value();
        // Ed25519 signatures are exactly 64 bytes
        if (sigBytes.size() != crypto_sign_ed25519_BYTES) {
            return stl::make_error<bool>("Invalid Ed25519 signature size");
        }
        // Verify
        int rc =
            crypto_sign_ed25519_verify_detached(sigBytes.data(), challengeBytes.data(), challengeBytes.size(), publicKey.keyData.data());
        // rc == 0 means valid, -1 means invalid
        return (rc == 0);
    }

    // Reading SSH private keys is complex because they can be:
    // - PEM format (-----BEGIN OPENSSH PRIVATE KEY-----)
    // - Old PEM format (-----BEGIN RSA PRIVATE KEY-----)
    // - Encrypted with a passphrase
    //
    // For simplicity, we only support unencrypted OpenSSH format Ed25519 keys.
    // This is what `ssh-keygen -t ed25519` generates by default (without -p).

    // Parse OpenSSH private key format
    // This is a simplified parser for unencrypted Ed25519 keys only
    static stl::result<std::vector<u8>> parse_openssh_private_key(std::string_view content) {
        // Find the base64 content between the markers
        const std::string begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
        const std::string end = "-----END OPENSSH PRIVATE KEY-----";
        auto beginPos = content.find(begin);
        auto endPos = content.find(end);
        if (beginPos == std::string_view::npos || endPos == std::string_view::npos) {
            return stl::make_error<std::vector<u8>>("Not an OpenSSH private key");
        }
        std::string base64Content;
        auto dataStart = beginPos + begin.size();
        auto dataEnd = endPos;
        for (usize i = dataStart; i < dataEnd; ++i) {
            char c = content[i];
            if (c != '\n' && c != '\r' && c != ' ') {
                base64Content += c;
            }
        }
        auto blobstl::result = base64_decode(base64Content);
        if (!blobstl::result) {
            return stl::make_error<std::vector<u8>>("Failed to decode private key base64");
        }
        return blobstl::result;
    }

    stl::result<std::string> sign_challenge(const std::filesystem::path& privateKeyPath, std::string_view challenge) {
        ensure_sodium_initialized();
        // Read private key file
        std::ifstream file(privateKeyPath);
        if (!file) {
            return stl::make_error<std::string>("Cannot open private key file: " + privateKeyPath.string());
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        // Parse OpenSSH format
        auto blobstl::result = parse_openssh_private_key(content);
        if (!blobstl::result) {
            return stl::make_error<std::string>(blobstl::result.error());
        }
        auto& blob = blobstl::result.value();
        // OpenSSH private key format is complex. The structure is:
        // - "openssh-key-v1\0" magic
        // - cipher name (string)
        // - kdf name (string)
        // - kdf options (string)
        // - number of keys (u32)
        // - public key(s)
        // - encrypted private key data
        //
        // For unencrypted keys, cipher="none", kdf="none"
        // The private key data contains the 64-byte Ed25519 secret key
        // (first 32 bytes are the seed, last 32 bytes are the public key)
        const std::string magic = "openssh-key-v1";
        if (blob.size() < magic.size() + 1) {
            return stl::make_error<std::string>("Private key too short");
        }
        if (std::memcmp(blob.data(), magic.c_str(), magic.size() + 1) != 0) {
            return stl::make_error<std::string>("Invalid OpenSSH key magic");
        }
        usize offset = magic.size() + 1;
        // Helper to read length-prefixed string
        auto readString = [&blob, &offset]() -> stl::result<std::string> {
            if (offset + 4 > blob.size()) {
                return stl::make_error<std::string>("Truncated key");
            }
            u32 len = read_be32(&blob[offset]);
            offset += 4;
            if (offset + len > blob.size()) {
                return stl::make_error<std::string>("Truncated key string");
            }
            std::string s(blob.begin() + offset, blob.begin() + offset + len);
            offset += len;
            return s;
        };
        // Read cipher name
        auto cipherstl::result = readString();
        if (!cipherstl::result)
            return stl::make_error<std::string>(cipherstl::result.error());
        if (cipherstl::result.value() != "none") {
            return stl::make_error<std::string>("Encrypted private keys are not supported. "
                                                "Use ssh-keygen -p to remove passphrase.");
        }
        // Read kdf name
        auto kdfstl::result = readString();
        if (!kdfstl::result)
            return stl::make_error<std::string>(kdfstl::result.error());
        // Read kdf options (skip)
        auto kdfOptsstl::result = readString();
        if (!kdfOptsstl::result)
            return stl::make_error<std::string>(kdfOptsstl::result.error());
        // Read number of keys
        if (offset + 4 > blob.size()) {
            return stl::make_error<std::string>("Truncated key (num keys)");
        }
        u32 numKeys = read_be32(&blob[offset]);
        offset += 4;
        if (numKeys != 1) {
            return stl::make_error<std::string>("Multiple keys in file not supported");
        }
        // Skip public key blob
        auto pubKeystl::result = readString();
        if (!pubKeystl::result)
            return stl::make_error<std::string>(pubKeystl::result.error());
        // Read private section
        auto privSectionstl::result = readString();
        if (!privSectionstl::result)
            return stl::make_error<std::string>(privSectionstl::result.error());
        auto& privSection = privSectionstl::result.value();
        // Private section format:
        // - checkint (u32) - repeated twice for verification
        // - checkint (u32)
        // - key type (string) "ssh-ed25519"
        // - public key (string) 32 bytes
        // - private key (string) 64 bytes (seed + public)
        // - comment (string)
        // - padding
        usize privOffset = 0;
        auto privBlob = std::vector<u8>(privSection.begin(), privSection.end());
        // Read and verify check ints
        if (privOffset + 8 > privBlob.size()) {
            return stl::make_error<std::string>("Private section too short");
        }
        u32 check1 = read_be32(&privBlob[privOffset]);
        privOffset += 4;
        u32 check2 = read_be32(&privBlob[privOffset]);
        privOffset += 4;
        if (check1 != check2) {
            return stl::make_error<std::string>("Private key check failed (wrong passphrase?)");
        }
        // Read key type
        if (privOffset + 4 > privBlob.size()) {
            return stl::make_error<std::string>("Truncated private section");
        }
        u32 typeLen = read_be32(&privBlob[privOffset]);
        privOffset += 4;
        if (privOffset + typeLen > privBlob.size()) {
            return stl::make_error<std::string>("Truncated key type");
        }
        std::string keyType(privBlob.begin() + privOffset, privBlob.begin() + privOffset + typeLen);
        privOffset += typeLen;
        if (keyType != "ssh-ed25519") {
            return stl::make_error<std::string>("Not an Ed25519 key: " + keyType);
        }
        // Skip public key
        if (privOffset + 4 > privBlob.size()) {
            return stl::make_error<std::string>("Truncated (pub key len)");
        }
        u32 pubLen = read_be32(&privBlob[privOffset]);
        privOffset += 4 + pubLen;
        // Read private key (64 bytes: 32-byte seed + 32-byte public)
        if (privOffset + 4 > privBlob.size()) {
            return stl::make_error<std::string>("Truncated (priv key len)");
        }
        u32 privLen = read_be32(&privBlob[privOffset]);
        privOffset += 4;
        if (privLen != crypto_sign_ed25519_SECRETKEYBYTES) {
            return stl::make_error<std::string>("Invalid Ed25519 private key length");
        }
        if (privOffset + privLen > privBlob.size()) {
            return stl::make_error<std::string>("Truncated private key data");
        }
        // Extract the 64-byte secret key
        std::vector<u8> secretKey(privBlob.begin() + privOffset, privBlob.begin() + privOffset + privLen);
        // Decode challenge
        auto challengestl::result = base64_decode(challenge);
        if (!challengestl::result) {
            return stl::make_error<std::string>("Invalid challenge encoding");
        }
        auto& challengeBytes = challengestl::result.value();
        // Sign
        std::vector<u8> signature(crypto_sign_ed25519_BYTES);
        crypto_sign_ed25519_detached(signature.data(), nullptr, challengeBytes.data(), challengeBytes.size(), secretKey.data());
        // Clear secret key from memory
        sodium_memzero(secretKey.data(), secretKey.size());
        return base64_encode(signature);
    }

    stl::result<std::string> load_public_key_file(const std::filesystem::path& path) {
        std::ifstream file(path);
        if (!file) {
            return stl::make_error<std::string>("Cannot open public key file: " + path.string());
        }
        std::string line;
        std::getline(file, line);
        // Trim whitespace
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        return line;
    }

    bool is_key_authorized(const std::vector<std::string>& authorizedKeys, std::string_view publicKey) {
        // Parse the public key to normalize it
        auto keystl::result = parse_public_key(publicKey);
        if (!keystl::result) {
            return false;
        }
        std::string normalizedKey = keystl::result.value().to_string();
        // Check against each authorized key
        for (const auto& authKey : authorizedKeys) {
            auto authstl::result = parse_public_key(authKey);
            if (authstl::result) {
                // Compare key data (ignore comments)
                if (authstl::result.value().keyData == keystl::result.value().keyData) {
                    return true;
                }
            }
        }
        return false;
    }

    stl::result<std::vector<std::string>> load_authorized_keys(const std::filesystem::path& path) {
        std::ifstream file(path);
        if (!file) {
            return stl::result<std::vector<std::string>>(error, "Cannot open authorized_keys: " + path.string());
        }
        std::vector<std::string> keys;
        std::string line;
        while (std::getline(file, line)) {
            // Skip empty lines and comments
            if (line.empty() || line[0] == '#') {
                continue;
            }
            // Trim whitespace
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' ')) {
                line.pop_back();
            }
            if (!line.empty()) {
                keys.push_back(line);
            }
        }
        return keys;
    }

} // namespace sap::sync
