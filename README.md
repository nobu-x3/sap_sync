# sap_sync

Sync protocol library for SapCloud ecosystem.

## Features

- **File Hashing**: Fast xxHash64-based file hashing for change detection
- **SSH Key Authentication**: Secure Ed25519 key-based authentication
- **Sync Protocol**: Last-write-wins sync algorithm with conflict resolution
- **Note Parsing**: YAML frontmatter and markdown parsing utilities
- **JSON Serialization**: Ready-to-use API types with nlohmann/json

## Building

### Standalone

```bash
cmake -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

### As a Submodule

```cmake
add_subdirectory(libs/sap_sync)
target_link_libraries(your_target PRIVATE sap::sync)
```

## Dependencies

- **sap_core**: Core types and utilities
- **xxHash**: Fast hashing (fetched automatically)
- **libsodium**: Cryptography for SSH auth (uses system library)
- **nlohmann/json**: JSON serialization (fetched automatically)

## Usage

### File Hashing

```cpp
#include <hash.h>

// Hash a string
std::string hash = sap::sync::hash_string("Hello, World!");

// Hash a file
auto result = sap::sync::hash_file("/path/to/file.txt");
if (result) {
    std::cout << "Hash: " << result.value() << "\n";
}

// Stream hashing for large data
sap::sync::StreamHasher hasher;
hasher.update(chunk1);
hasher.update(chunk2);
std::string hash = hasher.finalize();
```

### SSH Key Authentication

```cpp
#include <auth.h>

// Server: Generate challenge
std::string challenge = sap::sync::generate_challenge();

// Client: Sign challenge
auto sig = sap::sync::sign_challenge("~/.ssh/id_ed25519", challenge);

// Server: Verify signature
auto keyResult = sap::sync::parse_public_key(publicKeyStr);
auto verified = sap::sync::verify_signature(keyResult.value(), challenge, sig.value());
if (verified.value()) {
    // Authentication successful
    std::string token = sap::sync::generate_token();
}
```

### Sync Protocol

```cpp
#include <protocol.h>

// Compute what needs to be synced
auto operations = sap::sync::compute_sync_operations(localFiles, remoteFiles);

for (const auto& op : operations) {
    switch (op.action) {
        case ESyncAction::Download: /* ... */ break;
        case ESyncAction::Upload:   /* ... */ break;
        case ESyncAction::Delete:   /* ... */ break;
    }
}
```

### Note Parsing

```cpp
#include <protocol.h>

std::string markdown = R"(---
tags: [project, idea]
---
# My Note

Content here...)";

auto result = sap::sync::parse_note(markdown);
// result.value().title == "My Note"
// result.value().tags == {"project", "idea"}
// result.value().content == "# My Note\n\nContent here..."
```

## SSH Key Authentication Flow

```
Client                                    Server
  │                                         │
  │  1. POST /auth/challenge                │
  │  ──────────────────────────────────────>│
  │  { publicKey: "ssh-ed25519 AAAA..." }   │
  │                                         │
  │  2. Returns random challenge            │
  │  <──────────────────────────────────────│
  │  { challenge: "base64...", expires: T } │
  │                                         │
  │  3. Signs with PRIVATE key              │
  │  ──────────────────────────────────────>│
  │  POST /auth/verify                      │
  │  { publicKey, challenge, signature }    │
  │                                         │
  │  4. Verifies with PUBLIC key            │
  │  <──────────────────────────────────────│
  │  { token: "...", expiresAt: T }         │
  │                                         │
```
