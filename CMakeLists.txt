cmake_minimum_required(VERSION 3.25)
project(alfie_vault_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic -Werror)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wcovered-switch-default -Wnon-virtual-dtor)
endif()

# Dependencies: prefer the vendored third_party/ packages used on the Linux deploy box
# (no root apt permission there); fall back to system OpenSSL/Argon2 elsewhere.
set(VENDORED_ARGON2_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/argon2/usr/lib/x86_64-linux-gnu")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND EXISTS "${VENDORED_ARGON2_LIB_DIR}")
    set(OPENSSL_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libssl-dev/usr/include")
    set(OPENSSL_ARCH_HEADERS "${OPENSSL_HEADERS}/x86_64-linux-gnu")
    set(ARGON2_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/argon2/usr/include")
    set(ARGON2_LIB_DIR "${VENDORED_ARGON2_LIB_DIR}")

    find_library(CRYPTO_LIB NAMES crypto libcrypto.so.3 REQUIRED)
    find_library(SSL_LIB NAMES ssl libssl.so.3 REQUIRED)
    find_library(ARGON2_LIB NAMES argon2 PATHS "${ARGON2_LIB_DIR}" NO_DEFAULT_PATH REQUIRED)
else()
    find_package(OpenSSL 3 REQUIRED)
    get_target_property(OPENSSL_HEADERS OpenSSL::Crypto INTERFACE_INCLUDE_DIRECTORIES)
    set(OPENSSL_ARCH_HEADERS "${OPENSSL_HEADERS}")
    set(CRYPTO_LIB OpenSSL::Crypto)
    set(SSL_LIB OpenSSL::SSL)

    find_path(ARGON2_HEADERS argon2.h REQUIRED)
    find_library(ARGON2_LIB NAMES argon2 REQUIRED)
    get_filename_component(ARGON2_LIB_DIR "${ARGON2_LIB}" DIRECTORY)
endif()

# Thread-local SIGPIPE handling uses the platform pthread API.
find_package(Threads REQUIRED)

add_library(alfie_vault_core
    src/secure_memory.cpp
    src/ca.cpp
    src/vault.cpp
    src/http_unlock.cpp
    src/ipc_crypto.cpp
    src/ipc_transport.cpp
)

target_include_directories(alfie_vault_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${OPENSSL_HEADERS}
    ${OPENSSL_ARCH_HEADERS}
    ${ARGON2_HEADERS}
)

target_link_libraries(alfie_vault_core PUBLIC ${ARGON2_LIB} ${SSL_LIB} ${CRYPTO_LIB} Threads::Threads)
set_target_properties(alfie_vault_core PROPERTIES
    BUILD_RPATH "${ARGON2_LIB_DIR}"
)

add_executable(alfie-vault src/main.cpp)
target_link_libraries(alfie-vault PRIVATE alfie_vault_core)

include(CTest)

add_executable(test_ca tests/test_ca.cpp)
target_link_libraries(test_ca PRIVATE alfie_vault_core)
add_test(NAME ca COMMAND test_ca)

add_executable(test_vault tests/test_vault.cpp)
target_link_libraries(test_vault PRIVATE alfie_vault_core)
add_test(NAME vault COMMAND test_vault)

add_executable(test_ipc_crypto tests/test_ipc_crypto.cpp)
target_link_libraries(test_ipc_crypto PRIVATE alfie_vault_core)
add_test(NAME ipc_crypto COMMAND test_ipc_crypto)

add_executable(test_ipc_transport tests/test_ipc_transport.cpp)
target_link_libraries(test_ipc_transport PRIVATE alfie_vault_core)
add_test(NAME ipc_transport COMMAND test_ipc_transport)

add_executable(test_corruption tests/test_corruption.cpp)
target_link_libraries(test_corruption PRIVATE alfie_vault_core)
add_test(NAME corruption COMMAND test_corruption)

add_executable(test_secure_memory tests/test_secure_memory.cpp)
target_link_libraries(test_secure_memory PRIVATE alfie_vault_core)
add_test(NAME secure_memory COMMAND test_secure_memory)

add_executable(test_http_unlock tests/test_http_unlock.cpp)
target_link_libraries(test_http_unlock PRIVATE alfie_vault_core)
add_test(NAME http_unlock COMMAND test_http_unlock)

add_test(NAME init_smoke COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/init_smoke.py $<TARGET_FILE:alfie-vault>)
add_test(NAME https_smoke COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/https_smoke.py $<TARGET_FILE:alfie-vault>)
add_test(NAME gen_ip_cert COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gen_ip_cert.py)

set(CLANG_TOOLS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/clang-tools")
find_program(CLANG_FORMAT NAMES clang-format HINTS "${CLANG_TOOLS}/usr/bin")
find_program(CLANG_TIDY NAMES clang-tidy HINTS "${CLANG_TOOLS}/usr/bin")

foreach(TOOL clang-format clang-tidy)
    string(TOUPPER "${TOOL}" TOOL_VAR)
    string(REPLACE "-" "_" TOOL_VAR "${TOOL_VAR}")
    if(NOT ${TOOL_VAR})
        message(WARNING
            "${TOOL} not found on PATH or in third_party/clang-tools; "
            "the style targets that use it cannot run")
    endif()
endforeach()

# The vendored Linux clang-tools are a relocated .deb and need their bundled
# shared libraries on the loader path. Elsewhere the tool comes from PATH.
set(CLANG_ENV)
if(EXISTS "${CLANG_TOOLS}/usr/lib/x86_64-linux-gnu")
    set(CLANG_ENV "LD_LIBRARY_PATH=${CLANG_TOOLS}/usr/lib/x86_64-linux-gnu")
endif()

# clang-tidy reads compile_commands.json, which records Apple's /usr/bin/c++
# with no -isysroot: AppleClang resolves its own SDK implicitly, so CMake has no
# reason to spell it out. An upstream clang-tidy has no such default and fails
# to find <filesystem>. That failure is worse than it sounds -- clang-tidy still
# exits non-zero, but it reports diagnostics off the garbled AST, so the output
# names real files and lines while being wrong (a function read as a
# badly-named variable, enums re-flagged for a base type they already have).
# Pass the SDK explicitly so the analysis matches what the compiler saw.
set(TIDY_EXTRA_ARGS)
if(APPLE)
    set(TIDY_SYSROOT "${CMAKE_OSX_SYSROOT}")
    if(NOT TIDY_SYSROOT)
        execute_process(COMMAND xcrun --show-sdk-path
            OUTPUT_VARIABLE TIDY_SYSROOT
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET)
    endif()
    if(TIDY_SYSROOT)
        list(APPEND TIDY_EXTRA_ARGS
            --extra-arg=-isysroot --extra-arg=${TIDY_SYSROOT})
    else()
        message(WARNING
            "macOS SDK path not found (is xcrun available?); clang-tidy may "
            "fail to locate standard headers and report misleading findings")
    endif()
endif()

file(GLOB_RECURSE CPP_SOURCES CONFIGURE_DEPENDS src/*.cpp src/*.h tests/*.cpp)
file(GLOB_RECURSE CPP_TRANSLATION_UNITS CONFIGURE_DEPENDS src/*.cpp tests/*.cpp)

add_custom_target(format
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_FORMAT} -i ${CPP_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(format-check
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_FORMAT} --dry-run --Werror ${CPP_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(tidy
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_TIDY} ${TIDY_EXTRA_ARGS} --quiet -p ${CMAKE_BINARY_DIR} ${CPP_TRANSLATION_UNITS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# Restrict naming checks to translation units; their included headers are checked too.
add_custom_target(naming-check
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_TIDY} ${TIDY_EXTRA_ARGS}
        --quiet -p ${CMAKE_BINARY_DIR}
        --checks=-*,readability-identifier-naming
        --warnings-as-errors=readability-identifier-naming
        ${CPP_TRANSLATION_UNITS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# LLVM checks that apply to this standalone project (no LLVM/MLIR dependency).
add_custom_target(llvm-check
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_cpp_style.py
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_TIDY} ${TIDY_EXTRA_ARGS}
        --quiet -p ${CMAKE_BINARY_DIR}
        --checks=-*,llvm-else-after-return,llvm-include-order,llvm-namespace-comment,llvm-prefer-static-over-anonymous-namespace,llvm-qualified-auto,readability-identifier-naming,portability-avoid-pragma-once
        --warnings-as-errors=*
        ${CPP_TRANSLATION_UNITS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target(style-check DEPENDS format-check llvm-check)
