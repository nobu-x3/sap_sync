#include "hash.h"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <xxhash.h>

namespace sap::sync {
    // Convert 64-bit hash to 16-char hex string
    static std::string hash_to_hex(XXH64_hash_t hash) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0') << std::setw(16) << hash;
        return oss.str();
    }

    std::string hash_bytes(const void* data, size_t size) {
        XXH64_hash_t hash = XXH3_64bits(data, size);
        return hash_to_hex(hash);
    }

    std::string hash_string(std::string_view str) { return hash_bytes(str.data(), str.size()); }

    stl::result<std::string> hash_file(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return stl::make_error<std::string>("Failed to open file: {}", path.string());
        }
        // Use streaming hasher for memory efficiency
        StreamHasher hasher;
        constexpr size_t BUFFER_SIZE = 64 * 1024; // 64KB chunks
        std::vector<char> buffer(BUFFER_SIZE);
        while (file.read(buffer.data(), BUFFER_SIZE) || file.gcount() > 0) {
            hasher.update(buffer.data(), static_cast<size_t>(file.gcount()));
        }
        if (file.bad()) {
            return stl::make_error<std::string>("Error reading file: {}", path.string());
        }
        return hasher.finalize();
    }

    StreamHasher::StreamHasher() {
        m_State = XXH3_createState();
        XXH3_64bits_reset(static_cast<XXH3_state_t*>(m_State));
    }

    StreamHasher::~StreamHasher() {
        if (m_State) {
            XXH3_freeState(static_cast<XXH3_state_t*>(m_State));
        }
    }

    StreamHasher::StreamHasher(StreamHasher&& other) noexcept : m_State(other.m_State) { other.m_State = nullptr; }

    StreamHasher& StreamHasher::operator=(StreamHasher&& other) noexcept {
        if (this != &other) {
            if (m_State) {
                XXH3_freeState(static_cast<XXH3_state_t*>(m_State));
            }
            m_State = other.m_State;
            other.m_State = nullptr;
        }
        return *this;
    }

    void StreamHasher::update(const void* data, size_t size) { XXH3_64bits_update(static_cast<XXH3_state_t*>(m_State), data, size); }

    void StreamHasher::update(std::string_view str) { update(str.data(), str.size()); }

    std::string StreamHasher::finalize() {
        XXH64_hash_t hash = XXH3_64bits_digest(static_cast<XXH3_state_t*>(m_State));
        return hash_to_hex(hash);
    }

    void StreamHasher::reset() { XXH3_64bits_reset(static_cast<XXH3_state_t*>(m_State)); }
} // namespace sap::sync