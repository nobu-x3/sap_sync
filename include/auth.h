#pragma once

// #include <sap/core/types.h>
#include <chrono>
#include <nlohmann/json.hpp>
#include <optional>
#include <result.h>
#include <string>
#include <string_view>
#include <vector>

namespace sap::sync {
    constexpr size_t CHALLENGE_SIZE = 32; // 256 bits of randomness
    constexpr i64 CHALLENGE_EXPIRY_SECONDS = 300; // 5 minutes
    constexpr i64 TOKEN_EXPIRY_SECONDS = 86400; // 24 hours

    // Parsed SSH public key
    struct PublicKey {
        std::string algorithm; // "ssh-ed25519"
        std::vector<u8> keyData; // Raw key bytes (32 bytes for Ed25519)
        std::string comment; // Optional: "user@hostname"
        // Serialize back to SSH format: "ssh-ed25519 AAAA... comment"
        std::string to_string() const;
    };

    // Authentication challenge (server -> client)
    struct AuthChallenge {
        std::string challenge; // Random bytes, base64-encoded
        std::string publicKey; // The public key this challenge is for
        i64 expiresAt; // Unix timestamp (seconds)
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(AuthChallenge, challenge, publicKey, expiresAt)
    };

    // Challenge request (client -> server)
    struct ChallengeRequest {
        std::string publicKey; // SSH public key string
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(ChallengeRequest, publicKey)
    };

    // Verification request (client -> server)
    struct VerifyRequest {
        std::string publicKey; // SSH public key string
        std::string challenge; // The challenge that was signed
        std::string signature; // Ed25519 signature, base64-encoded
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(VerifyRequest, publicKey, challenge, signature)
    };

    // Authentication token (server -> client)
    struct AuthToken {
        std::string token; // Opaque token string
        i64 expiresAt; // Unix timestamp (seconds)
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(AuthToken, token, expiresAt)
    };

    // Parse an SSH public key string (e.g., "ssh-ed25519 AAAA... user@host")
    // Returns error if format is invalid or algorithm is unsupported
    stl::result<PublicKey> parse_public_key(std::string_view keyString);

    // Server-Side Functions

    // Generate a cryptographically secure random challenge
    // Returns base64-encoded random bytes
    std::string generate_challenge();

    // Verify an Ed25519 signature
    // - publicKey: Parsed public key (must be Ed25519)
    // - challenge: The original challenge bytes (base64-encoded)
    // - signature: The signature to verify (base64-encoded)
    // Returns true if signature is valid, false otherwise
    stl::result<bool> verify_signature(const PublicKey& publicKey, std::string_view challenge, std::string_view signature);

    // Generate a secure random token for authenticated sessions
    std::string generate_token();

    // Client-Side Functions

    // Sign a challenge using a private key file
    // - privateKeyPath: Path to SSH private key (e.g., ~/.ssh/id_ed25519)
    // - challenge: The challenge to sign (base64-encoded)
    // Returns: base64-encoded signature
    // Note: Supports only unencrypted Ed25519 keys for now
    stl::result<std::string> sign_challenge(const std::filesystem::path& privateKeyPath, std::string_view challenge);

    // Load public key from file (e.g., ~/.ssh/id_ed25519.pub)
    stl::result<std::string> load_public_key_file(const std::filesystem::path& path);

    std::string base64_encode(const void* data, size_t size);
    std::string base64_encode(const std::vector<u8>& data);
    stl::result<std::vector<u8>> base64_decode(std::string_view encoded);

    // Check if a public key is in the authorized_keys list
    bool is_key_authorized(const std::vector<std::string>& authorizedKeys, std::string_view publicKey);

    // Load authorized keys from file (one key per line, SSH format)
    stl::result<std::vector<std::string>> load_authorized_keys(const std::filesystem::path& path);

} // namespace sap::sync
