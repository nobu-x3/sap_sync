#include <fstream>
#include <gtest/gtest.h>
#include "hash.h"
#include "auth.h"

TEST(HashTest, HashBytes) {
    std::string data = "Hello, World!";
    std::string hash = sap::sync::hash_bytes(data.data(), data.size());
    EXPECT_EQ(hash.length(), 16); // 64-bit hash = 16 hex chars
    // Same input should produce same hash
    std::string hash2 = sap::sync::hash_bytes(data.data(), data.size());
    EXPECT_EQ(hash, hash2);
}

TEST(HashTest, HashString) {
    std::string hash1 = sap::sync::hash_string("test");
    std::string hash2 = sap::sync::hash_string("test");
    std::string hash3 = sap::sync::hash_string("different");
    EXPECT_EQ(hash1, hash2);
    EXPECT_NE(hash1, hash3);
}

TEST(HashTest, StreamHasher) {
    sap::sync::StreamHasher hasher;
    hasher.update("Hello, ");
    hasher.update("World!");
    std::string streamHash = hasher.finalize();
    std::string directHash = sap::sync::hash_string("Hello, World!");
    EXPECT_EQ(streamHash, directHash);
}

TEST(HashTest, StreamHasherReset) {
    sap::sync::StreamHasher hasher;
    hasher.update("first");
    hasher.finalize();
    hasher.reset();
    hasher.update("second");
    std::string hash = hasher.finalize();
    EXPECT_EQ(hash, sap::sync::hash_string("second"));
}

TEST(HashTest, HashFile) {
    // Create temp file
    auto tempPath = std::filesystem::temp_directory_path() / "sap_sync_hash_test.txt";
    {
        std::ofstream f(tempPath);
        f << "File content for hashing";
    }
    auto result = sap::sync::hash_file(tempPath);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result.value().length(), 16);
    // Hash should match string hash of content
    EXPECT_EQ(result.value(), sap::sync::hash_string("File content for hashing"));
    std::filesystem::remove(tempPath);
}

TEST(HashTest, HashFileNotFound) {
    auto result = sap::sync::hash_file("/nonexistent/path/file.txt");
    EXPECT_FALSE(result.has_value());
}

TEST(Base64Test, EncodeDecodeRoundtrip) {
    std::vector<u8> original = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0x42};
    std::string encoded = sap::sync::base64_encode(original);
    auto decoded = sap::sync::base64_decode(encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value(), original);
}

TEST(Base64Test, EncodeKnownValue) {
    std::string input = "Hello";
    std::string encoded = sap::sync::base64_encode(input.data(), input.size());
    EXPECT_EQ(encoded, "SGVsbG8=");
}

TEST(Base64Test, DecodeInvalid) {
    auto result = sap::sync::base64_decode("!!invalid!!");
    EXPECT_FALSE(result.has_value());
}

TEST(AuthTest, ParseValidEd25519Key) {
    // This is a valid Ed25519 public key format (generated for testing)
    std::string keyStr = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example";
    auto result = sap::sync::parse_public_key(keyStr);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result.value().algorithm, "ssh-ed25519");
    EXPECT_EQ(result.value().key_data.size(), 32); // Ed25519 keys are 32 bytes
    EXPECT_EQ(result.value().comment, "test@example");
}

TEST(AuthTest, ParseKeyWithoutComment) {
    std::string keyStr = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    auto result = sap::sync::parse_public_key(keyStr);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_TRUE(result.value().comment.empty());
}

TEST(AuthTest, RejectUnsupportedAlgorithm) {
    std::string keyStr = "ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host";
    auto result = sap::sync::parse_public_key(keyStr);
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(result.error().find("ssh-ed25519") != std::string::npos);
}

TEST(AuthTest, RejectInvalidFormat) {
    auto result = sap::sync::parse_public_key("not a valid key");
    EXPECT_FALSE(result.has_value());
}

TEST(AuthTest, GenerateChallengeUnique) {
    std::string c1 = sap::sync::generate_challenge();
    std::string c2 = sap::sync::generate_challenge();
    EXPECT_NE(c1, c2); // Should be unique
    // Should be valid base64
    auto decoded = sap::sync::base64_decode(c1);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().size(), sap::sync::CHALLENGE_SIZE);
}

TEST(AuthTest, GenerateTokenUnique) {
    std::string t1 = sap::sync::generate_token();
    std::string t2 = sap::sync::generate_token();
    EXPECT_NE(t1, t2);
}

TEST(AuthTest, KeyAuthorization) {
    std::vector<std::string> authorizedKeys = {
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user1@host",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHPbLVmwNhNBJKYk0/e5W9u5z0K7TxT5LZnQSM7wW3F user2@host",
    };
    // Key with different comment should still match
    std::string testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl different@comment";
    EXPECT_TRUE(sap::sync::is_key_authorized(authorizedKeys, testKey));
    // Unknown key should not match
    std::string unknownKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJZPklS9XqMwkpKGpKYFPE9xQbS5gKL3e2Q5d1K2Z0m8 unknown@host";
    EXPECT_FALSE(sap::sync::is_key_authorized(authorizedKeys, unknownKey));
}