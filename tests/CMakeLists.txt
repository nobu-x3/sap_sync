include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(sap_sync_tests
    sync_tests.cpp
)

target_link_libraries(sap_sync_tests
    PRIVATE
        sap::sync
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(sap_sync_tests)