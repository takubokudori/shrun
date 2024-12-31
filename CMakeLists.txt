cmake_minimum_required(VERSION 3.29)
project(shrun C)

set(CMAKE_C_STANDARD 23)

add_executable(shrun src/main.c src/shrun.h src/shrun.c)
add_library(shrun_lib SHARED src/shrun.h src/shrun.c src/shrun.def)

set_property(TARGET shrun_lib PROPERTY LINKER_LANGUAGE C)
set_target_properties(shrun_lib PROPERTIES OUTPUT_NAME "shrun" PREFIX "")
