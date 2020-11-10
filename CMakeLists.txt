cmake_minimum_required(VERSION 3.2)

project(rc5_implementation)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -o3")

set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})

set(PROJECT_INSTALL_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(PROJECT_INSTALL_BIN_DIR ${PROJECT_SOURCE_DIR}/bin)
set(PROJECT_INSTALL_LIB_DIR ${PROJECT_SOURCE_DIR}/lib)

include_directories(${PROJECT_INSTALL_INCLUDE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/src/RC5)

add_subdirectory(src)
add_subdirectory(test)


