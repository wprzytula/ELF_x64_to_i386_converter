cmake_minimum_required(VERSION 3.21)
project(Zad1_ELF_converter)

set(CMAKE_CXX_STANDARD 20)

add_executable(converter
        err.cc
        converter.cc
        assemblage.cc assemblage.h converter.h)
