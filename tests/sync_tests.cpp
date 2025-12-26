#include <fstream>
#include <gtest/gtest.h>
#include "hash.h"
#include "auth.h"
#include "protocol.h"

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

using namespace sap::sync;

class SyncOperationTest : public ::testing::Test {
protected:
    FileMetadata makeFile(const std::string& path, const std::string& hash,
                          Timestamp mtime, bool deleted = false) {
        FileMetadata f;
        f.path = path;
        f.hash = hash;
        f.size = 100;
        f.mtime = mtime;
        f.created_at = 1000;
        f.updated_at = mtime;
        f.is_deleted = deleted;
        return f;
    }
};

TEST_F(SyncOperationTest, FileOnlyOnServer) {
    auto remote = makeFile("test.txt", "abc", 1000);
    auto action = determine_action(std::nullopt, remote);
    EXPECT_EQ(action, ESyncAction::Download);
}

TEST_F(SyncOperationTest, FileOnlyOnClient) {
    auto local = makeFile("test.txt", "abc", 1000);
    auto action = determine_action(local, std::nullopt);
    EXPECT_EQ(action, ESyncAction::Upload);
}

TEST_F(SyncOperationTest, FilesInSync) {
    auto local = makeFile("test.txt", "abc", 1000);
    auto remote = makeFile("test.txt", "abc", 1000);
    auto action = determine_action(local, remote);
    EXPECT_EQ(action, ESyncAction::None);
}

TEST_F(SyncOperationTest, ServerNewer) {
    auto local = makeFile("test.txt", "old", 1000);
    auto remote = makeFile("test.txt", "new", 2000);
    auto action = determine_action(local, remote);
    EXPECT_EQ(action, ESyncAction::Download);
}

TEST_F(SyncOperationTest, ClientNewer) {
    auto local = makeFile("test.txt", "new", 2000);
    auto remote = makeFile("test.txt", "old", 1000);
    auto action = determine_action(local, remote);
    EXPECT_EQ(action, ESyncAction::Upload);
}

TEST_F(SyncOperationTest, DeletedOnServer) {
    auto local = makeFile("test.txt", "abc", 1000);
    auto remote = makeFile("test.txt", "abc", 1000, true);
    auto action = determine_action(local, remote);
    EXPECT_EQ(action, ESyncAction::Delete);
}

TEST_F(SyncOperationTest, ComputeOperations) {
    std::vector<FileMetadata> local = {
        makeFile("both.txt", "same", 1000),
        makeFile("local-only.txt", "local", 1000),
        makeFile("client-newer.txt", "new", 2000),
    };
    std::vector<FileMetadata> remote = {
        makeFile("both.txt", "same", 1000),
        makeFile("remote-only.txt", "remote", 1000),
        makeFile("client-newer.txt", "old", 1000),
    };
    auto ops = compute_sync_operations(local, remote);
    // Should have 3 operations: download remote-only, upload local-only, upload client-newer
    EXPECT_EQ(ops.size(), 3);
    // Find each operation
    bool foundDownload = false, foundUploadLocal = false, foundUploadNewer = false;
    for (const auto& op : ops) {
        if (op.path == "remote-only.txt" && op.action == ESyncAction::Download) {
            foundDownload = true;
        }
        if (op.path == "local-only.txt" && op.action == ESyncAction::Upload) {
            foundUploadLocal = true;
        }
        if (op.path == "client-newer.txt" && op.action == ESyncAction::Upload) {
            foundUploadNewer = true;
        }
    }
    EXPECT_TRUE(foundDownload);
    EXPECT_TRUE(foundUploadLocal);
    EXPECT_TRUE(foundUploadNewer);
}

TEST(NoteParsingTest, ParseWithFrontmatter) {
    std::string content = R"(---
tags: [project, idea]
---
# My Note Title

Some content here.)";
    auto result = parse_note(content);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().title, "My Note Title");
    EXPECT_EQ(result.value().tags.size(), 2);
    EXPECT_EQ(result.value().tags[0], "project");
    EXPECT_EQ(result.value().tags[1], "idea");
    EXPECT_TRUE(result.value().content.find("Some content") != std::string::npos);
}

TEST(NoteParsingTest, ParseWithoutFrontmatter) {
    std::string content = "# Simple Note\n\nJust content.";
    auto result = parse_note(content);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().title, "Simple Note");
    EXPECT_TRUE(result.value().tags.empty());
}

TEST(NoteParsingTest, ParseNoHeading) {
    std::string content = "This is just text without a heading.";
    auto result = parse_note(content);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().title, "This is just text without a heading.");
}

TEST(NoteParsingTest, SerializeNote) {
    ParsedNote note;
    note.title = "Test";
    note.content = "# Test\n\nContent";
    note.tags = {"tag1", "tag2"};
    std::string serialized = serialize_note(note);
    EXPECT_TRUE(serialized.find("tags: [tag1, tag2]") != std::string::npos);
    EXPECT_TRUE(serialized.find("# Test") != std::string::npos);
}

TEST(NoteParsingTest, GeneratePreview) {
    std::string content = "# Heading\n\nThis is **bold** and _italic_ text.\n\nMore content.";
    std::string preview = generate_preview(content, 50);
    EXPECT_LE(preview.length(), 53);  // 50 + "..."
    EXPECT_TRUE(preview.find("**") == std::string::npos);  // Markdown removed
    EXPECT_TRUE(preview.find("_") == std::string::npos);
}

TEST(UUIDTest, GenerateUnique) {
    std::string uuid1 = generate_uuid();
    std::string uuid2 = generate_uuid();
    EXPECT_NE(uuid1, uuid2);
}

TEST(UUIDTest, ValidFormat) {
    std::string uuid = generate_uuid();
    // Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    EXPECT_EQ(uuid.length(), 36);
    EXPECT_EQ(uuid[8], '-');
    EXPECT_EQ(uuid[13], '-');
    EXPECT_EQ(uuid[14], '4');  // Version 4
    EXPECT_EQ(uuid[18], '-');
    EXPECT_EQ(uuid[23], '-');
    // Variant should be 8, 9, a, or b
    char variant = uuid[19];
    EXPECT_TRUE(variant == '8' || variant == '9' || variant == 'a' || variant == 'b');
}

TEST(JsonTest, FileMetadata) {
    FileMetadata f;
    f.path = "test/file.txt";
    f.hash = "abc123";
    f.size = 1024;
    f.mtime = 1234567890;
    f.created_at = 1234567800;
    f.updated_at = 1234567890;
    f.is_deleted = false;
    nlohmann::json j = f;
    EXPECT_EQ(j["path"], "test/file.txt");
    EXPECT_EQ(j["hash"], "abc123");
    EXPECT_EQ(j["size"], 1024);
    // Deserialize
    FileMetadata f2 = j.get<FileMetadata>();
    EXPECT_EQ(f2.path, f.path);
    EXPECT_EQ(f2.hash, f.hash);
}

TEST(JsonTest, NoteUpdateRequestOptionalFields) {
    NoteUpdateRequest req;
    req.title = "New Title";
    // content and tags are not set
    nlohmann::json j = req;
    EXPECT_TRUE(j.contains("title"));
    EXPECT_FALSE(j.contains("content"));
    EXPECT_FALSE(j.contains("tags"));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}