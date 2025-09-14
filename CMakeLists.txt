cmake_minimum_required(VERSION 3.13)
project(aes_in_c VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Enable compiler warnings for better code quality
if(MSVC)
  # Microsoft Visual C++ compiler warnings
  # /W4 enables a high level of warnings. /WX treats warnings as errors.
  add_compile_options(/W4 /WX)
else()
  # GCC/Clang compiler warnings
  # -Wall -Wextra -Wpedantic enable a wide range of warnings.
  # -Werror treats warnings as errors.
  # -Wconversion and -Wsign-conversion warn about potentially unsafe type conversions.
  add_compile_options(-Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
endif()

# Library target
add_library(aes STATIC src/aes.c)
target_include_directories(aes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Test executable
add_executable(test_aes tests/test_aes.c)
target_link_libraries(test_aes PRIVATE aes)

# Optional: Add testing with CTest
enable_testing()
add_test(NAME aes_tests COMMAND test_aes)