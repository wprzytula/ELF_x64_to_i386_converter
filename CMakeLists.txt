cmake_minimum_required(VERSION 3.21)
project(Zad1_ELF_converter)

set(CMAKE_CXX_STANDARD 20)

#set(CMAKE_CXX_COMPILER "/usr/bin/clang++")

add_executable(converter
        err.cc
        converter.cc
        assemblage.cc assemblage.h converter.h elf64.cc elf32.cc stubs.cc)
