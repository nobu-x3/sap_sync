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
option(SAP_SYNC_INSTALL "Generate install target" ${PROJECT_IS_TOP_LEVEL})

if(NOT TARGET sap::core)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/sap_core/CMakeLists.txt)
        add_subdirectory(sap_core)
    else()
        message(STATUS "sap_sync: sap::core not found, fetching...")
        FetchContent_Declare(
            sap_core
            GIT_REPOSITORY https://github.com/nobu-x3/sap_core.git
            GIT_TAG        main
        )
        FetchContent_MakeAvailable(sap_core)
    endif()
endif()

if(NOT TARGET xxHash::xxhash)
    message(STATUS "sap_sync: Fetching xxHash...")
    FetchContent_Declare(
        xxhash
        GIT_REPOSITORY https://github.com/Cyan4973/xxHash.git
        GIT_TAG        v0.8.2
        SOURCE_SUBDIR  cmake_unofficial
    )
    set(XXHASH_BUILD_XXHSUM OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(xxhash)
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM QUIET libsodium)
endif()

if(NOT SODIUM_FOUND)
    find_library(SODIUM_LIBRARY NAMES sodium libsodium)
    find_path(SODIUM_INCLUDE_DIR NAMES sodium.h)
    if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
        set(SODIUM_FOUND TRUE)
        set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
        set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
    endif()
endif()

if(NOT SODIUM_FOUND)
    message(STATUS "sap_sync: libsodium not found, fetching...")
    FetchContent_Declare(
        libsodium
        GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
        GIT_TAG        1.0.19-RELEASE
    )
    FetchContent_MakeAvailable(libsodium)
    set(SODIUM_LIBRARIES sodium)
    set(SODIUM_INCLUDE_DIRS ${libsodium_SOURCE_DIR}/src/libsodium/include)
endif()

if(NOT TARGET nlohmann_json::nlohmann_json)
    message(STATUS "sap_sync: Fetching nlohmann_json...")
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3
    )
    set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(nlohmann_json)
endif()