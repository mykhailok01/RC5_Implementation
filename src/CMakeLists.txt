cmake_minimum_required(VERSION 3.2)
project(project_src)

add_subdirectory(RC5)

add_subdirectory(MD5)
include_directories(MD5)

add_subdirectory(argparse)
include_directories(argparse/include)

add_subdirectory(ConsoleClient)