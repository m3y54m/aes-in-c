cmake_minimum_required(VERSION 3.13)
project(aes_in_c C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Collect sources
file(GLOB AES_SRC "src/*.c")
add_library(aes STATIC ${AES_SRC})

add_executable(test_aes tests/test_aes.c)
target_include_directories(test_aes PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_aes PRIVATE aes)
