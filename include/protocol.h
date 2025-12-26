#pragma once

#include <functional>
#include <result.h>
#include <vector>
#include "sync_types.h"

namespace sap::sync {

    // The sync protocol determines what operations are needed to bring a client
    // in sync with the server (or vice versa).
    //
    // LAST-WRITE-WINS STRATEGY:
    // When the same file is modified on both client and server, the version
    // with the most recent mtime wins. This is simple and predictable, though
    // it can lose data if you're not careful (edit on two devices offline,
    // one version will be overwritten).
    //
    // SYNC FLOW:
    // 1. Client requests server state: GET /api/v1/sync/state?since=<last_sync>
    // 2. Server returns list of files with their hashes and mtimes
    // 3. Client compares each file:
    //    - Same hash → in sync, skip
    //    - File only on server → download
    //    - File only on client → upload
    //    - Different hash, server newer → download
    //    - Different hash, client newer → upload
    //    - Deleted on server → delete locally
    //    - Deleted locally → delete on server
    // 4. Client executes operations
    // 5. Client stores server_time as last_sync for next delta sync

    // Compare local and remote file lists to determine sync operations
    std::vector<SyncOperation> compute_sync_operations(const std::vector<FileMetadata>& localFiles,
                                                       const std::vector<FileMetadata>& remoteFiles);

    // Determine action for a single file
    ESyncAction determine_action(const std::optional<FileMetadata>& local, const std::optional<FileMetadata>& remote);

    // Abstract interface for implementing sync on client or server.
    class ISyncClient {
    public:
        virtual ~ISyncClient() = default;
        // Fetch server sync state
        virtual stl::result<SyncState> fetch_sync_state(std::optional<Timestamp> since) = 0;
        // Download a file from server
        virtual stl::result<std::vector<u8>> download_file(std::string_view path) = 0;
        // Upload a file to server
        virtual stl::result<FileMetadata> upload_file(std::string_view path, const std::vector<u8>& content, Timestamp mtime) = 0;
        // Delete a file on server
        virtual stl::result<> delete_file(std::string_view path) = 0;
    };

    class ISyncStorage {
    public:
        virtual ~ISyncStorage() = default;
        // Get all local file metadata
        virtual stl::result<std::vector<FileMetadata>> get_local_files() = 0;
        // Read a local file
        virtual stl::result<std::vector<u8>> read_file(std::string_view path) = 0;
        // Write a local file
        virtual stl::result<> write_file(std::string_view path, const std::vector<u8>& content, Timestamp mtime) = 0;
        // Delete a local file
        virtual stl::result<> delete_file(std::string_view path) = 0;
        // Update local file metadata
        virtual stl::result<> update_metadata(const FileMetadata& meta) = 0;
    };

    // Executes sync operations against a client and storage.
    struct SyncProgress {
        size_t total_operations;
        size_t completed_operations;
        size_t downloaded_bytes;
        size_t uploaded_bytes;
        std::string current_file;
    };

    using SyncProgressCallback = std::function<void(const SyncProgress&)>;

    struct SyncResult {
        bool success;
        size_t files_downloaded;
        size_t files_uploaded;
        size_t files_deleted;
        size_t errors;
        std::vector<std::string> error_messages;
        Timestamp last_sync_time;
    };

    SyncResult execute_sync(ISyncClient& client, ISyncStorage& storage, std::optional<Timestamp> lastSync,
                            SyncProgressCallback progress_callback = nullptr);

    struct ParsedNote {
        std::string title;
        std::vector<std::string> tags;
        std::string content; // Content without frontmatter
        std::string raw_content; // Original content with frontmatter
    };

    // Parse a note's markdown content
    stl::result<ParsedNote> parse_note(std::string_view content);

    // Serialize a note back to markdown with frontmatter
    std::string serialize_note(const ParsedNote& note);

    // Extract title from markdown (first # heading or first line)
    std::string extract_title(std::string_view content);

    // Generate preview text (first ~200 chars, stripped of markdown)
    std::string generate_preview(std::string_view content, size_t max_length = 200);

    // Generate a random UUID v4 string (e.g., "550e8400-e29b-41d4-a716-446655440000")
    std::string generate_uuid();

} // namespace sap::sync
