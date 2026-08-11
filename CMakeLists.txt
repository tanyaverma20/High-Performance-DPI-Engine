cmake_minimum_required(VERSION 3.16)
project(DPIEngine VERSION 1.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# C++17 required throughout
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Compiler warnings  (Phase 1 requirement)
# ---------------------------------------------------------------------------
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# Threads  (required for the multi-threaded DPI pipeline)
# ---------------------------------------------------------------------------
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------------
include_directories(${CMAKE_SOURCE_DIR}/include)

# ---------------------------------------------------------------------------
# Library-level source files (shared between the DPI executable and the tests)
# ---------------------------------------------------------------------------
set(DPI_LIB_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/types.cpp
    src/sni_extractor.cpp
    src/tcp_reassembler.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/dpi_engine.cpp
    src/profiler.cpp
    src/parser_pool.cpp
)

# ---------------------------------------------------------------------------
# Production executable: dpi_engine
#
# Canonical entry point: src/main_dpi.cpp
# The following files were moved to legacy/ and are NOT compiled:
#   legacy/main_viewer.cpp   (was src/main.cpp)
#   legacy/main_simple.cpp   (was src/main_simple.cpp)
#   legacy/main_working.cpp  (was src/main_working.cpp)
#   legacy/dpi_mt.cpp        (was src/dpi_mt.cpp)
# ---------------------------------------------------------------------------
add_executable(dpi_engine
    src/main_dpi.cpp
    ${DPI_LIB_SOURCES}
)

target_link_libraries(dpi_engine PRIVATE Threads::Threads)

# ---------------------------------------------------------------------------
# Benchmark executable: dpi_benchmark
# ---------------------------------------------------------------------------
add_executable(dpi_benchmark
    tests/benchmark.cpp
    ${DPI_LIB_SOURCES}
)

target_link_libraries(dpi_benchmark PRIVATE Threads::Threads)

# ---------------------------------------------------------------------------
# Test executable: dpi_tests
#
# Uses the same library sources, but a separate main in tests/.
# No external test framework — lightweight assert()-based harness.
# ---------------------------------------------------------------------------
add_executable(dpi_tests
    tests/test_correctness.cpp
    ${DPI_LIB_SOURCES}
)

target_link_libraries(dpi_tests PRIVATE Threads::Threads)

# Register with CTest so `ctest` works from the build directory
enable_testing()
add_test(NAME correctness COMMAND dpi_tests)

# ---------------------------------------------------------------------------
# Optional sanitizer build
# Enable with:  cmake -DENABLE_ASAN=ON -DENABLE_UBSAN=ON ..
# ---------------------------------------------------------------------------
option(ENABLE_ASAN "Build with AddressSanitizer" OFF)
option(ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TSAN "Build with ThreadSanitizer" OFF)

set(SANITIZERS "")
if(ENABLE_ASAN AND NOT MSVC)
    list(APPEND SANITIZERS "address")
endif()
if(ENABLE_UBSAN AND NOT MSVC)
    list(APPEND SANITIZERS "undefined")
endif()
if(ENABLE_TSAN AND NOT MSVC)
    list(APPEND SANITIZERS "thread")
endif()

if(SANITIZERS)
    list(JOIN SANITIZERS "," SANITIZER_LIST)
    target_compile_options(dpi_engine    PRIVATE -fsanitize=${SANITIZER_LIST} -fno-omit-frame-pointer)
    target_link_options(dpi_engine       PRIVATE -fsanitize=${SANITIZER_LIST})
    target_compile_options(dpi_tests     PRIVATE -fsanitize=${SANITIZER_LIST} -fno-omit-frame-pointer)
    target_link_options(dpi_tests        PRIVATE -fsanitize=${SANITIZER_LIST})
    target_compile_options(dpi_benchmark PRIVATE -fsanitize=${SANITIZER_LIST} -fno-omit-frame-pointer)
    target_link_options(dpi_benchmark PRIVATE -fsanitize=${SANITIZER_LIST})
    message(STATUS "Sanitizers enabled: ${SANITIZER_LIST}")
endif()
