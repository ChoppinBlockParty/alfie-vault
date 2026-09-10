cmake_minimum_required(VERSION 3.25)
project(alfie_vault_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic)

set(OPENSSL_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libssl-dev/usr/include")
set(OPENSSL_ARCH_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libssl-dev/usr/include/x86_64-linux-gnu")
set(ARGON2_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/argon2/usr/include")
set(ARGON2_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/argon2/usr/lib/x86_64-linux-gnu")

find_library(CRYPTO_LIB NAMES crypto libcrypto.so.3 REQUIRED)
find_library(SSL_LIB NAMES ssl libssl.so.3 REQUIRED)
find_library(ARGON2_LIB NAMES argon2 PATHS "${ARGON2_LIB_DIR}" NO_DEFAULT_PATH REQUIRED)

add_library(alfie_vault_core
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

target_link_libraries(alfie_vault_core PUBLIC ${ARGON2_LIB} ${SSL_LIB} ${CRYPTO_LIB})
set_target_properties(alfie_vault_core PROPERTIES
    BUILD_RPATH "${ARGON2_LIB_DIR}"
)

add_executable(alfie-vault src/main.cpp)
target_link_libraries(alfie-vault PRIVATE alfie_vault_core)

include(CTest)

add_executable(test_vault tests/test_vault.cpp)
target_link_libraries(test_vault PRIVATE alfie_vault_core)
add_test(NAME vault COMMAND test_vault)

add_executable(test_ipc_crypto tests/test_ipc_crypto.cpp)
target_link_libraries(test_ipc_crypto PRIVATE alfie_vault_core)
add_test(NAME ipc_crypto COMMAND test_ipc_crypto)

add_executable(test_ipc_transport tests/test_ipc_transport.cpp)
target_link_libraries(test_ipc_transport PRIVATE alfie_vault_core)
add_test(NAME ipc_transport COMMAND test_ipc_transport)

add_executable(test_http_unlock tests/test_http_unlock.cpp)
target_link_libraries(test_http_unlock PRIVATE alfie_vault_core)
add_test(NAME http_unlock COMMAND test_http_unlock)

add_test(NAME https_smoke COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/https_smoke.py $<TARGET_FILE:alfie-vault>)
add_test(NAME gen_ip_cert COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gen_ip_cert.py)

set(CLANG_TOOLS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/clang-tools")
set(CLANG_ENV "LD_LIBRARY_PATH=${CLANG_TOOLS}/usr/lib/x86_64-linux-gnu")
set(CLANG_FORMAT "${CLANG_TOOLS}/usr/bin/clang-format")
set(CLANG_TIDY "${CLANG_TOOLS}/usr/bin/clang-tidy")
file(GLOB_RECURSE CPP_SOURCES CONFIGURE_DEPENDS src/*.cpp src/*.hpp tests/*.cpp)

add_custom_target(format
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_FORMAT} -i ${CPP_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(format-check
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_FORMAT} --dry-run --Werror ${CPP_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(tidy
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_TIDY} --quiet -p ${CMAKE_BINARY_DIR} ${CPP_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
