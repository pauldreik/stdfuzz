# Copyright Paul Dreik 2023
# Licensed under Boost software license 1.0
# SPDX-License-Identifier: BSL-1.0

cmake_minimum_required(VERSION 3.25)

project(stdfuzz)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(-Wall -Wextra)

add_compile_options(-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -O1)
add_link_options(-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)

set(fuzzersrcfiles
    charconv/charconv.cpp
    charconv/roundtrip-floatingpoint.cpp
    charconv/roundtrip-int.cpp
    chrono/chrono-parse.cpp
    format/chrono-duration.cpp
    format/one-arg.cpp
    format/one-warg.cpp
    format/two-args.cpp
    libstdcpp/unicode-utf-iterator.cpp
    regex/regex.cpp
    set_like/set_differential.cpp
)

# assume using clang with a local gcc trunk (currently gcc 14) installation
set(GCCDIR $ENV{HOME}/local/)
set(GCCVERSION 14.0.1)

foreach(fuzzersrcfile ${fuzzersrcfiles})
    string(REPLACE / - fuzzer ${fuzzersrcfile})
    cmake_path(REPLACE_EXTENSION fuzzer)
    add_executable(${fuzzer} ${fuzzersrcfile})
    target_compile_options(${fuzzer} PUBLIC -nostdinc++ -nostdinc)
    target_include_directories(${fuzzer} PRIVATE helpers)
    # these can be obtained by executing  ~/local/bin/g++ -E -Wp,-v - </dev/null
    target_compile_options(${fuzzer} PUBLIC "SHELL:-cxx-isystem ${GCCDIR}/include/c++/${GCCVERSION}/" )
    target_compile_options(${fuzzer} PUBLIC "SHELL:-cxx-isystem ${GCCDIR}/include/c++/${GCCVERSION}/x86_64-pc-linux-gnu/" )
    target_compile_options(${fuzzer} PUBLIC "SHELL:-cxx-isystem ${GCCDIR}/lib/gcc/x86_64-pc-linux-gnu/${GCCVERSION}/include")
    target_compile_options(${fuzzer} PUBLIC "SHELL:-cxx-isystem /usr/local/include")
    target_compile_options(${fuzzer} PUBLIC "SHELL:-cxx-isystem ${GCCDIR}/include")
    target_compile_options(${fuzzer} PUBLIC "SHELL:-cxx-isystem ${GCCDIR}/lib/gcc/x86_64-pc-linux-gnu/${GCCVERSION}/include-fixed")
    target_compile_options(${fuzzer} PUBLIC "SHELL:-cxx-isystem /usr/include/x86_64-linux-gnu")
    target_compile_options(${fuzzer} PUBLIC "SHELL:-cxx-isystem /usr/include/")
    # this is needed for clang<=16
#    target_compile_definitions(${fuzzer} PUBLIC __cplusplus=202302L)
    target_link_libraries(${fuzzer} PUBLIC ${GCCDIR}/lib64/libstdc++.a)
endforeach()

