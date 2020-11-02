cmake_minimum_required(VERSION 3.2)
project(unit_tests)

add_subdirectory(lib/googletest)
include_directories(lib/googletest/googletest/include)

set(SOURCE_FILES main.cpp src/RC5_tests.cpp)

add_executable(unit_tests ${SOURCE_FILES})
target_link_libraries(unit_tests gtest)
install(TARGETS unit_tests DESTINATION bin)
