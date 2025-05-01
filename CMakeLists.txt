cmake_minimum_required(VERSION 3.25)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BUILD_SHARED_LIBS OFF)

option(NULLGATE_BUILD_SAMPLE "Build sample" OFF)
option(NULLGATE_CROSSCOMPILE "Crosscompile from linux to windows(uses mingw)" OFF)

if (NULLGATE_CROSSCOMPILE)
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
    set(CMAKE_ASM_COMPILER x86_64-w64-mingw32-g++)
endif()

project(nullgate CXX ASM)
project(sample)

# Nullgate
add_library(nullgate
    ./src/nullgate/syscalls.S
    ./src/nullgate/syscalls.cpp
    ./src/nullgate/obfuscation.cpp
    ./include/nullgate/syscalls.hpp
    ./include/nullgate/obfuscation.hpp
)

target_include_directories(nullgate
    PUBLIC ./include/
)

target_compile_features(nullgate
    PUBLIC cxx_std_23
)

target_compile_options(nullgate
    PRIVATE -s -O3
)

target_link_options(nullgate
    PUBLIC -static
)

if(NULLGATE_BUILD_SAMPLE)
    add_executable(sample
        ./src/sample/sample.cpp
    )

    target_include_directories(sample
        PRIVATE ./include/
    )

    target_link_libraries(sample
        PRIVATE nullgate
    )
endif()

# Hasher
add_subdirectory(
    ./src/hasher/
)
