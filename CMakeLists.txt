cmake_minimum_required(VERSION 3.18)
project(bench_bip352 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================================
# Compiler flag equalization.
#
# UltrafastSecp256k1's CMake injects -O3 -march=native via target_compile_options
# (PRIVATE + INTERFACE), which we cannot easily override from a parent CMakeLists.
# libsecp256k1's CMake explicitly downgrades -O3 to -O2 and adds no -march flag.
#
# To make the comparison fair, we upgrade libsecp256k1 AFTER add_subdirectory
# to match UF's flags. With GCC, the last -O flag wins.
# ============================================================================

# --- UltrafastSecp256k1 (CPU library only, no tests/bench/examples/GPU) ---
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCH OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCH_COMPARE OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CABI OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_METAL OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_OPENCL OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CUDA OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_ROCM OFF CACHE BOOL "" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(UltrafastSecp256k1)

# --- libsecp256k1 (static, no tests/bench/examples) ---
# Use prefixed variable names to avoid conflicts with UltrafastSecp256k1's CMake
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
add_subdirectory(secp256k1)

# Upgrade libsecp256k1 to match UF's optimization: -O3 -march=native.
# libsecp256k1's CMake forces -O2; appending -O3 overrides it (last flag wins in GCC).
# Also add -march=native to match UF's auto-detected ARCH_FLAGS.
target_compile_options(secp256k1 PRIVATE -O3 -march=native)

# --- Benchmark executables ---
add_executable(bench_ufsecp bench_ufsecp.cpp)
target_link_libraries(bench_ufsecp PRIVATE fastsecp256k1)

add_executable(bench_libsecp bench_libsecp.c)
target_link_libraries(bench_libsecp PRIVATE secp256k1)

# Per-operation detail benchmarks
add_executable(bench_ufsecp_detail bench_ufsecp_detail.cpp)
target_link_libraries(bench_ufsecp_detail PRIVATE fastsecp256k1)

add_executable(bench_libsecp_detail bench_libsecp_detail.c)
target_link_libraries(bench_libsecp_detail PRIVATE secp256k1)
