cmake_minimum_required(VERSION 3.17)
project(Gtrace)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")     


# Use clang as compiler
SET (CMAKE_C_COMPILER             "/usr/bin/clang")
SET (CMAKE_C_FLAGS                "-Wall -std=c99")
SET (CMAKE_C_FLAGS_DEBUG          "-g")
SET (CMAKE_C_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
SET (CMAKE_C_FLAGS_RELEASE        "-O4 -DNDEBUG")
SET (CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g")
SET (CMAKE_CXX_COMPILER             "/usr/bin/clang++")
SET (CMAKE_CXX_FLAGS                "-Wall")
SET (CMAKE_CXX_FLAGS_DEBUG          "-g")
SET (CMAKE_CXX_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELEASE        "-O4 -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
SET (CMAKE_AR      "/usr/bin/llvm-ar")
SET (CMAKE_LINKER  "/usr/bin/llvm-ld")
SET (CMAKE_NM      "/usr/bin/llvm-nm")
SET (CMAKE_OBJDUMP "/usr/bin/llvm-objdump")
SET (CMAKE_RANLIB  "/usr/bin/llvm-ranlib")

find_package(LibElf REQUIRED)
find_package(LibDwarf REQUIRED)
find_package(PkgConfig REQUIRED)

set(PKG_CONFIG_EXECUTABLE "/usr/bin/pkg-config")
pkg_check_modules (CAPSTONE REQUIRED capstone)

set(SOURCE_FILES 
    gtrace.cc
    
    syscall_nums.h
    pretty_print.c
    pretty_print.h
    utils.c
    utils.h

    elf_parser.h)

       

# Add executable target with source files listed in SOURCE_FILES variable
add_executable(gtrace ${SOURCE_FILES})


target_include_directories(gtrace
    PUBLIC /usr/include
    PUBLIC ${LIBELF_INCLUDE_DIRS}
    PUBLIC ${LIBDWARF_INCLUDE_DIRS}
    PUBLIC ${CAPSTONE_INCLUDE_DIRS}
    PRIVATE ${PROJECT_SOURCE_DIR})


target_link_libraries(gtrace 
    PUBLIC ${LIBELF_LIBRARIES}
    PUBLIC ${LIBDWARF_LIBRARIES}
    PUBLIC ${CAPSTONE_LIBRARIES})

target_compile_features(gtrace PRIVATE cxx_std_17)

