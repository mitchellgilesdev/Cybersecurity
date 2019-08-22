cmake_minimum_required(VERSION 3.10)
project(untitled1 C)

set(CMAKE_C_STANDARD 99)

add_executable(untitled main.c)

link_directories(/usr/lib/x86_64-linux-gnu/)
link_libraries(/usr/lib/x86_64-linux-gnu/libssl.so)
include_directories(/usr/include/openssl)

target_link_libraries(untitled -lcrypto)
target_link_libraries(untitled -ldl)