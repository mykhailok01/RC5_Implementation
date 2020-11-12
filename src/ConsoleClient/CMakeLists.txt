cmake_minimum_required(VERSION 3.2)
project(console_client)
set(COMMON_SOURCE_FILE Common.hpp Common.cpp)
add_library(common ${COMMON_SOURCE_FILE})
target_link_libraries(common md5)
install(TARGETS common DESTINATION ${PROJECT_INSTALL_LIB_DIR})

set(ENCRYPT_SOURCE_FILES EncryptMain.cpp)
add_executable(encrypt ${ENCRYPT_SOURCE_FILES})
target_link_libraries(encrypt common)

set(DECRYPT_SOURCE_FILES DecryptMain.cpp)
add_executable(decrypt ${DECRYPT_SOURCE_FILES})
target_link_libraries(decrypt common)

install(TARGETS decrypt encrypt DESTINATION ${PROJECT_INSTALL_BIN_DIR})