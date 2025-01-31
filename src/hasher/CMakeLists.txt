cmake_minimum_required(VERSION 3.25)

if (NULLGATE_CROSSCOMPILE)
    set(CMAKE_CXX_COMPILER /usr/bin/g++)
    set(CMAKE_ASM_COMPILER /usr/bin/g++)
endif()

project(hasher)

add_executable(hasher
    ./hasher.cpp
    ../nullgate/obfuscation.cpp
)

target_include_directories(hasher
    PRIVATE ../../include/
)
