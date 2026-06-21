cmake_minimum_required(VERSION 3.22.1)
project(ForceServerGlobalResource LANGUAGES CXX)

add_library(ForceServerGlobalResource SHARED src/main.cpp)
target_compile_features(ForceServerGlobalResource PRIVATE cxx_std_20)
target_compile_options(ForceServerGlobalResource PRIVATE -fvisibility=hidden -ffunction-sections -fdata-sections -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(ForceServerGlobalResource PRIVATE log)
set_target_properties(ForceServerGlobalResource PROPERTIES OUTPUT_NAME "ForceServerGlobalResource")
