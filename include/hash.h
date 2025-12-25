#include <filesystem>
#include <result.h>
#include <string>
#include <vector>

namespace sap::sync {

    // =============================================================================
    // File Hashing
    // =============================================================================
    // We use xxHash64 for file hashing because:
    //   1. It's extremely fast (faster than MD5, SHA1, etc.)
    //   2. Good distribution (low collision probability for our use case)
    //   3. We don't need cryptographic security for sync (just change detection)
    //
    // The hash is returned as a 16-character lowercase hex string (64 bits).
    // Example: "a1b2c3d4e5f67890"
    // =============================================================================

    // Hash raw bytes
    std::string hash_bytes(const void* data, size_t size);

    // Hash a string
    std::string hash_string(std::string_view str);

    // Hash a file by reading it in chunks (memory efficient for large files)
    stl::result<std::string> hash_file(const std::filesystem::path& path);

    // Hash a vector of bytes
    inline std::string hash_blob(const std::vector<u8>& blob) { return hash_bytes(blob.data(), blob.size()); }

    class StreamHasher {
    public:
        StreamHasher();
        ~StreamHasher();
        StreamHasher(const StreamHasher&) = delete;
        StreamHasher& operator=(const StreamHasher&) = delete;
        StreamHasher(StreamHasher&& other) noexcept;
        StreamHasher& operator=(StreamHasher&& other) noexcept;

        // Add data to hash
        void update(const void* data, size_t size);

        void update(std::string_view str);

        // Finalize and get hash (can only be called once)
        std::string finalize();

        // Reset to initial state for reuse
        void reset();

    private:
        void* m_State; // Opaque pointer to XXH3_state_t
    };
} // namespace sap::sync