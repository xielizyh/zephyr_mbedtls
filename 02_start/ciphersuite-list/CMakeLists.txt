# 设置CMake最低版本限制
cmake_minimum_required(VERSION 3.8.2)
# 设置工程名
project("Ciphersuite-list")
# 添加头文件路径
include_directories(./ $ENV{MBEDTLS_BASE}/include)
# 将mbedtls源文件路径到MBEDTLS_SOURCES变量中
aux_source_directory($ENV{MBEDTLS_BASE}/library MBEDTLS_SOURCES)

# 定义SOURCES变量的源文件
set(SOUCRES
        ${CMAKE_CURRENT_LIST_DIR}/ciphersuite-list.c
        ${MBEDTLS_SOURCES})

# 添加可执行文件
add_executable(ciphersuite-list ${SOUCRES})