# Toolchain file for GCC
if(NOT DEFINED CMAKE_SYSTEM_NAME)
	if(WIN32)
		set(CMAKE_SYSTEM_NAME Windows)
	elseif(UNIX AND NOT APPLE)
		set(CMAKE_SYSTEM_NAME Linux)
	elseif(APPLE)
		set(CMAKE_SYSTEM_NAME Darwin)
	endif()
endif()

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)
