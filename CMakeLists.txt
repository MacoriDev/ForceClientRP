cmake_minimum_required(VERSION 3.22)
project(ForceClientRP LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(ForceClientRP SHARED
    src/main.cpp
)

target_compile_options(ForceClientRP PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
    -fvisibility=hidden
)

target_link_libraries(ForceClientRP PRIVATE
    dl
)
