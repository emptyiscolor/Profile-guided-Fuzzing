cmake_minimum_required(VERSION 3.14)
project(AbstractFS)

set(CMAKE_C_STANDARD 11)

# file(LOADER_SRC src/fs_rt.c)

include_directories(${CMAKE_SOURCE_DIR}/include)
link_directories(${CMAKE_SOURCE_DIR}/lib)

add_library(fs_hook SHARED
    src/fs_rt.c
    src/fcache.c
    )

add_compile_definitions(DISABLE_OUTPUT)

target_link_libraries(fs_hook funchook)

add_executable(sample src/examples/sample.c)

target_link_libraries(sample dl)

set_target_properties(fs_hook PROPERTIES PREFIX "")
# target_compile_options(fs_hook PRIVATE -Wall)