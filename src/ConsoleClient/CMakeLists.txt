cmake_minimum_required(VERSION 3.2)
project(console_client)
set(ENCRYPT_SOURCE_FILES EncryptMain.cpp)
add_executable(encrypt ${ENCRYPT_SOURCE_FILES})

set(DECRYPT_SOURCE_FILES DecryptMain.cpp)
add_executable(decrypt ${DECRYPT_SOURCE_FILES})
install(TARGETS decrypt encrypt DESTINATION ${PROJECT_INSTALL_BIN_DIR})