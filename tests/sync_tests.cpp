#include <gtest/gtest.h>
#include <fstream>
#include "hash.h"

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