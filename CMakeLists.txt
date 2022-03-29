cmake_minimum_required(VERSION 3.21)
project(Zad1_ELF_converter)

set(CMAKE_CXX_STANDARD 17)

#set(CMAKE_CXX_COMPILER "/usr/bin/clang++")

set (SOURCES
        err.cc
        assemblage.cc
        assemblage.h
        converter.h
        elf64.cc
        elf32.cc
        stubs.cc func_spec.cc)

add_executable(converter ${SOURCES} converter.cc)
add_executable(tests ${SOURCES} tests.cc)
