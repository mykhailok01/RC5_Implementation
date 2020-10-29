cmake_minimum_required(VERSION 3.2)
project(project_src)

add_subdirectory(RC5)
set(SOURCE_FILES main.cpp)

add_executable(project_src ${SOURCE_FILES})
install(TARGETS project_src DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})
