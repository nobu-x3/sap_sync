cmake_minimum_required(VERSION 3.20)
project(sap_sync
    VERSION 0.1.0
    DESCRIPTION "Sync protocol library for SapCloud"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SAP_SYNC_BUILD_TESTS "Build sap_sync tests" ${PROJECT_IS_TOP_LEVEL})

add_library(sap_sync STATIC
    src/hash.cpp
    src/auth.cpp
    src/protocol.cpp
)
add_library(sap::sync ALIAS sap_sync)

add_subdirectory(sap_core)

set(XXHASH_BUILD_XXHSUM OFF CACHE BOOL "" FORCE)
add_subdirectory(xxHash/cmake_unofficial)

set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
add_subdirectory(json)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)
endif()

target_include_directories(sap_sync
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/xxHash>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sap_core/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/json/include>
        $<INSTALL_INTERFACE:include>
        ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(sap_sync
    PUBLIC
        nlohmann_json::nlohmann_json
    PRIVATE
        xxHash::xxhash
        ${SODIUM_LIBRARIES}
)

target_compile_features(sap_sync PUBLIC cxx_std_20)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sap_sync PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(sap_sync PRIVATE /W4)
endif()

if(SAP_SYNC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()