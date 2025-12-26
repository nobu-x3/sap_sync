#include "protocol.h"
#include <algorithm>
#include <iomanip>
#include <random>
#include <regex>
#include <sstream>
#include <unordered_map>
#include "hash.h"

namespace sap::sync {

    ESyncAction determine_action(const std::optional<FileMetadata>& local, const std::optional<FileMetadata>& remote) {
        // Case 1: File only exists on server
        if (!local && remote) {
            if (remote->is_deleted) {
                return ESyncAction::None; // Already deleted everywhere
            }
            return ESyncAction::Download;
        }
        // Case 2: File only exists locally
        if (local && !remote) {
            if (local->is_deleted) {
                return ESyncAction::None; // Already deleted everywhere
            }
            return ESyncAction::Upload;
        }
        // Case 3: File exists on neither (shouldn't happen, but handle it)
        if (!local && !remote) {
            return ESyncAction::None;
        }
        // Case 4: File exists on both
        // Both deleted
        if (local->is_deleted && remote->is_deleted) {
            return ESyncAction::None;
        }
        // Remote deleted, local not
        if (remote->is_deleted && !local->is_deleted) {
            return ESyncAction::Delete; // Propagate deletion locally
        }
        // Local deleted, remote not
        if (local->is_deleted && !remote->is_deleted) {
            return ESyncAction::Delete; // Propagate deletion to server
        }
        // Same content (hashes match)
        if (local->hash == remote->hash) {
            return ESyncAction::None;
        }
        // Different content - use mtime to decide (last write wins)
        if (remote->mtime > local->mtime) {
            return ESyncAction::Download;
        } else if (local->mtime > remote->mtime) {
            return ESyncAction::Upload;
        }
        // Same mtime but different hash (rare edge case)
        // Default to server version
        return ESyncAction::Download;
    }

    std::vector<SyncOperation> compute_sync_operations(const std::vector<FileMetadata>& local_files,
                                                       const std::vector<FileMetadata>& remote_files) {
        // Build maps for O(1) lookup
        std::unordered_map<std::string, const FileMetadata*> local_map;
        std::unordered_map<std::string, const FileMetadata*> remote_map;
        for (const auto& f : local_files) {
            local_map[f.path] = &f;
        }
        for (const auto& f : remote_files) {
            remote_map[f.path] = &f;
        }
        // Collect all unique paths
        std::vector<std::string> all_paths;
        for (const auto& f : local_files) {
            all_paths.push_back(f.path);
        }
        for (const auto& f : remote_files) {
            if (local_map.find(f.path) == local_map.end()) {
                all_paths.push_back(f.path);
            }
        }
        // Compute operations
        std::vector<SyncOperation> operations;
        for (const auto& path : all_paths) {
            std::optional<FileMetadata> local;
            std::optional<FileMetadata> remote;
            auto local_it = local_map.find(path);
            auto remote_it = remote_map.find(path);
            if (local_it != local_map.end()) {
                local = *local_it->second;
            }
            if (remote_it != remote_map.end()) {
                remote = *remote_it->second;
            }
            ESyncAction action = determine_action(local, remote);
            if (action != ESyncAction::None) {
                operations.push_back({path, action, local, remote});
            }
        }
        return operations;
    }

    SyncResult execute_sync(ISyncClient& client, ISyncStorage& storage, std::optional<Timestamp> last_sync,
                            SyncProgressCallback progress_callback) {
        SyncResult result{};
        result.success = true;
        // Step 1: Fetch server state
        auto state_result = client.fetch_sync_state(last_sync);
        if (!state_result) {
            result.success = false;
            result.errors = 1;
            result.error_messages.push_back("Failed to fetch sync state: " + state_result.error());
            return result;
        }
        auto& server_state = state_result.value();
        result.last_sync_time = server_state.server_time;
        // Step 2: Get local files
        auto local_result = storage.get_local_files();
        if (!local_result) {
            result.success = false;
            result.errors = 1;
            result.error_messages.push_back("Failed to get local files: " + local_result.error());
            return result;
        }
        // Step 3: Compute sync operations
        auto operations = compute_sync_operations(local_result.value(), server_state.files);
        // Progress tracking
        SyncProgress progress{};
        progress.total_operations = operations.size();
        // Step 4: Execute operations
        for (const auto& op : operations) {
            progress.current_file = op.path;
            if (progress_callback) {
                progress_callback(progress);
            }
            switch (op.action) {
            case ESyncAction::Download:
                {
                    auto download_result = client.download_file(op.path);
                    if (!download_result) {
                        result.errors++;
                        result.error_messages.push_back("Download failed: " + op.path + " - " + download_result.error());
                        continue;
                    }
                    auto& content = download_result.value();
                    progress.downloaded_bytes += content.size();
                    Timestamp mtime = op.remote_meta ? op.remote_meta->mtime : now_ms();
                    auto write_result = storage.write_file(op.path, content, mtime);
                    if (!write_result) {
                        result.errors++;
                        result.error_messages.push_back("Write failed: " + op.path + " - " + write_result.error());
                        continue;
                    }
                    result.files_downloaded++;
                    break;
                }
            case ESyncAction::Upload:
                {
                    auto read_result = storage.read_file(op.path);
                    if (!read_result) {
                        result.errors++;
                        result.error_messages.push_back("Read failed: " + op.path + " - " + read_result.error());
                        continue;
                    }
                    auto& content = read_result.value();
                    Timestamp mtime = op.local_meta ? op.local_meta->mtime : now_ms();
                    progress.uploaded_bytes += content.size();
                    auto upload_result = client.upload_file(op.path, content, mtime);
                    if (!upload_result) {
                        result.errors++;
                        result.error_messages.push_back("Upload failed: " + op.path + " - " + upload_result.error());
                        continue;
                    }
                    // Update local metadata with server response
                    storage.update_metadata(upload_result.value());
                    result.files_uploaded++;
                    break;
                }
            case ESyncAction::Delete:
                {
                    // If remote is deleted, delete locally
                    if (op.remote_meta && op.remote_meta->is_deleted) {
                        auto delete_result = storage.delete_file(op.path);
                        if (!delete_result) {
                            result.errors++;
                            result.error_messages.push_back("Local delete failed: " + op.path);
                        }
                    }
                    // If local is deleted, delete on server
                    else if (op.local_meta && op.local_meta->is_deleted) {
                        auto delete_result = client.delete_file(op.path);
                        if (!delete_result) {
                            result.errors++;
                            result.error_messages.push_back("Remote delete failed: " + op.path);
                        }
                    }
                    result.files_deleted++;
                    break;
                }
            default:
                break;
            }
            progress.completed_operations++;
        }
        if (result.errors > 0) {
            result.success = false;
        }
        return result;
    }

    stl::result<ParsedNote> parse_note(std::string_view content) {
        ParsedNote note;
        note.raw_content = std::string{content};
        // Check for frontmatter
        if (content.size() >= 4 && content.substr(0, 4) == "---\n") {
            auto end_pos = content.find("\n---\n", 4);
            if (end_pos == std::string_view::npos) {
                end_pos = content.find("\n---", 4);
            }
            if (end_pos != std::string_view::npos) {
                auto frontmatter = content.substr(4, end_pos - 4);
                note.content = std::string(content.substr(end_pos + 5));
                // Simple YAML parsing for tags
                // Look for "tags: [tag1, tag2]" or "tags:\n  - tag1\n  - tag2"
                std::string fm_str(frontmatter);
                auto tags_pos = fm_str.find("tags:");
                if (tags_pos != std::string::npos) {
                    auto line_end = fm_str.find('\n', tags_pos);
                    auto tags_line =
                        fm_str.substr(tags_pos + 5, line_end == std::string::npos ? std::string::npos : line_end - tags_pos - 5);
                    // Trim
                    while (!tags_line.empty() && tags_line[0] == ' ') {
                        tags_line = tags_line.substr(1);
                    }
                    // Array format: [tag1, tag2]
                    if (!tags_line.empty() && tags_line[0] == '[') {
                        auto close_pos = tags_line.find(']');
                        if (close_pos != std::string::npos) {
                            auto tag_list = tags_line.substr(1, close_pos - 1);
                            std::istringstream iss{tag_list};
                            std::string tag;
                            while (std::getline(iss, tag, ',')) {
                                // Trim whitespace and quotes
                                while (!tag.empty() && (tag[0] == ' ' || tag[0] == '"' || tag[0] == '\'')) {
                                    tag = tag.substr(1);
                                }
                                while (!tag.empty() && (tag.back() == ' ' || tag.back() == '"' || tag.back() == '\'')) {
                                    tag.pop_back();
                                }
                                if (!tag.empty()) {
                                    note.tags.push_back(tag);
                                }
                            }
                        }
                    }
                    // List format: - tag1
                    else if (tags_line.empty() || tags_line[0] == '\n') {
                        std::regex list_pattern{R"(^\s*-\s+(.+)$)"};
                        std::istringstream lines{fm_str.substr(tags_pos + 5)};
                        std::string line;
                        while (std::getline(lines, line)) {
                            std::smatch match;
                            if (std::regex_match(line, match, list_pattern)) {
                                std::string tag = match[1].str();
                                // Trim
                                while (!tag.empty() && tag.back() == ' ') {
                                    tag.pop_back();
                                }
                                note.tags.push_back(tag);
                            } else if (!line.empty() && line[0] != ' ' && line[0] != '-') {
                                break; // End of tags list
                            }
                        }
                    }
                }
            } else {
                note.content = std::string(content);
            }
        } else {
            note.content = std::string(content);
        }
        // Extract title
        note.title = extract_title(note.content);
        return note;
    }

    std::string serialize_note(const ParsedNote& note) {
        std::ostringstream oss;
        // Write frontmatter if there are tags
        if (!note.tags.empty()) {
            oss << "---\n";
            oss << "tags: [";
            for (size_t i = 0; i < note.tags.size(); ++i) {
                if (i > 0)
                    oss << ", ";
                oss << note.tags[i];
            }
            oss << "]\n";
            oss << "---\n";
        }
        oss << note.content;
        return oss.str();
    }

    std::string extract_title(std::string_view content) {
        // Skip leading whitespace
        while (!content.empty() && (content[0] == ' ' || content[0] == '\n')) {
            content = content.substr(1);
        }
        // Look for # heading
        if (!content.empty() && content[0] == '#') {
            auto line_end = content.find('\n');
            auto heading = content.substr(0, line_end);
            // Remove leading #s and whitespace
            while (!heading.empty() && heading[0] == '#') {
                heading = heading.substr(1);
            }
            while (!heading.empty() && heading[0] == ' ') {
                heading = heading.substr(1);
            }
            return std::string(heading);
        }
        // Use first line as title
        auto line_end = content.find('\n');
        std::string first_line{content.substr(0, line_end)};
        // Truncate if too long
        if (first_line.length() > 100) {
            first_line = first_line.substr(0, 97) + "...";
        }
        return first_line;
    }

    std::string generate_preview(std::string_view content, size_t max_length) {
        std::string preview;
        preview.reserve(max_length);
        bool last_was_space = false;
        for (char c : content) {
            if (preview.length() >= max_length) {
                break;
            }
            // Skip markdown syntax
            if (c == '#' || c == '*' || c == '_' || c == '`' || c == '[' || c == ']') {
                continue;
            }
            // Collapse whitespace
            if (c == '\n' || c == '\r' || c == '\t') {
                c = ' ';
            }
            if (c == ' ') {
                if (last_was_space)
                    continue;
                last_was_space = true;
            } else {
                last_was_space = false;
            }
            preview += c;
        }
        // Trim
        while (!preview.empty() && preview.back() == ' ') {
            preview.pop_back();
        }
        if (preview.length() >= max_length && !preview.empty()) {
            preview = preview.substr(0, max_length - 3) + "...";
        }
        return preview;
    }

    std::string generate_uuid() {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        static std::uniform_int_distribution<u64> dis;
        u64 part1 = dis(gen);
        u64 part2 = dis(gen);
        // Set version (4) and variant bits
        part1 = (part1 & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
        part2 = (part2 & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        oss << std::setw(8) << ((part1 >> 32) & 0xFFFFFFFF) << "-";
        oss << std::setw(4) << ((part1 >> 16) & 0xFFFF) << "-";
        oss << std::setw(4) << (part1 & 0xFFFF) << "-";
        oss << std::setw(4) << ((part2 >> 48) & 0xFFFF) << "-";
        oss << std::setw(12) << (part2 & 0xFFFFFFFFFFFFULL);
        return oss.str();
    }

} // namespace sap::sync
