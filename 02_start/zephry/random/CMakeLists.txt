# 设置CMake最低版本限制
cmake_minimum_required(VERSION 3.8.2)
# 设置工程名
project("Random")
# 添加构建脚本biolerplate.cmake
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)

# 添加所有源文件.c
FILE(GLOB app_sources src/*.c)
# 添加依赖的.c文件，并构建名为app的可执行固件
target_sources(app PRIVATE ${app_sources})