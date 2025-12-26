#pragma once

#include <types.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace sap::sync {

// We use milliseconds since Unix epoch for timestamps.
// This gives us sub-second precision while being simple to work with.
using Timestamp = i64;  // Milliseconds since Unix epoch

inline Timestamp now_ms() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

// Represents metadata about a file in the sync system.
// Used to determine which files need to be synced without transferring content.
struct FileMetadata {
    std::string path;       // Relative path from storage root (e.g., "notes/abc.md")
    std::string hash;       // xxHash64 of file content (hex string)
    i64 size;               // File size in bytes
    Timestamp mtime;        // Last modification time (ms since epoch)
    Timestamp created_at;    // Creation time (ms since epoch)
    Timestamp updated_at;    // Last metadata update time (ms since epoch)
    bool is_deleted;         // Soft delete flag (for sync propagation)
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(FileMetadata, path, hash, size, mtime, 
                                   created_at, updated_at, is_deleted)
};

// Notes are files with additional metadata (title, tags).
// The content is stored as markdown with YAML frontmatter.
struct NoteMetadata {
    std::string id;                 // UUID
    std::string path;               // File path (e.g., "notes/{id}.md")
    std::string title;              // Note title (extracted from content)
    std::vector<std::string> tags;  // Tags for organization
    std::string hash;               // Content hash
    Timestamp created_at;
    Timestamp updated_at;
    bool is_deleted;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(NoteMetadata, id, path, title, tags, hash,
                                   created_at, updated_at, is_deleted)
};

// Response from GET /api/v1/sync/state
// Contains all file metadata needed for client to determine what to sync.
struct SyncState {
    Timestamp server_time;               // Server's current time
    std::vector<FileMetadata> files;    // All files (or changed since lastSync)
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(SyncState, server_time, files)
};

// Enum describing what action the client should take for each file.
enum class ESyncAction {
    None,       // File is in sync, no action needed
    Download,   // Server has newer version, download it
    Upload,     // Client has newer version, upload it
    Delete,     // File was deleted, propagate deletion
    Conflict    // Both sides modified (shouldn't happen with last-write-wins)
};

struct SyncOperation {
    std::string path;
    ESyncAction action;
    std::optional<FileMetadata> local_meta;   // Client's metadata (if exists)
    std::optional<FileMetadata> remote_meta;  // Server's metadata (if exists)
};

struct FileUploadRequest {
    std::string path;
    Timestamp mtime;
    std::string content_base64;  // For JSON transport; raw bytes for multipart
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(FileUploadRequest, path, mtime, content_base64)
};

struct FileUploadResponse {
    std::string path;
    std::string hash;
    Timestamp mtime;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(FileUploadResponse, path, hash, mtime)
};

struct NoteCreateRequest {
    std::string title;
    std::string content;
    std::vector<std::string> tags;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(NoteCreateRequest, title, content, tags)
};

struct NoteUpdateRequest {
    std::optional<std::string> title;
    std::optional<std::string> content;
    std::optional<std::vector<std::string>> tags;
    // Manual JSON handling for optional fields
};

inline void to_json(nlohmann::json& j, const NoteUpdateRequest& r) {
    if (r.title) j["title"] = *r.title;
    if (r.content) j["content"] = *r.content;
    if (r.tags) j["tags"] = *r.tags;
}

inline void from_json(const nlohmann::json& j, NoteUpdateRequest& r) {
    if (j.contains("title")) r.title = j["title"].get<std::string>();
    if (j.contains("content")) r.content = j["content"].get<std::string>();
    if (j.contains("tags")) r.tags = j["tags"].get<std::vector<std::string>>();
}

struct NoteResponse {
    std::string id;
    std::string title;
    std::string content;
    std::vector<std::string> tags;
    Timestamp created_at;
    Timestamp updated_at;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(NoteResponse, id, title, content, tags,
                                   created_at, updated_at)
};

struct NoteListItem {
    std::string id;
    std::string title;
    std::vector<std::string> tags;
    Timestamp updated_at;
    std::string preview;  // First ~200 chars of content
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(NoteListItem, id, title, tags, updated_at, preview)
};

struct NoteListResponse {
    std::vector<NoteListItem> notes;
    i64 total;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(NoteListResponse, notes, total)
};

struct TagInfo {
    std::string name;
    i64 count;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(TagInfo, name, count)
};

struct TagListResponse {
    std::vector<TagInfo> tags;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(TagListResponse, tags)
};

struct ErrorResponse {
    std::string error;
    std::string message;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ErrorResponse, error, message)
};

} // namespace sap::sync
