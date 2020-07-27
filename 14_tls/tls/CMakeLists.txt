if (CONFIG_ZEPHYR_ENV)

# 设置CMake最低版本限制
cmake_minimum_required(VERSION 3.8.2)
# 设置工程名
project("tls")
# 添加构建脚本biolerplate.cmake
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)

# 添加mbedTLS配置文件路径(!!!编译不过)
# if (CONFIG_MBEDTLS)
# target_include_directories(mbedTLS INTERFACE ${PROJECT_SOURCE_DIR}/src)
# endif()

# 添加头文件路径
include_directories(./ $ENV{MBEDTLS_BASE}/include)
# 将mbedtls源文件路径到MBEDTLS_SOURCES变量中
aux_source_directory($ENV{MBEDTLS_BASE}/library MBEDTLS_SOURCES)

# 添加依赖的.c文件，并构建名为app的可执行固件
target_sources(app PRIVATE ${MBEDTLS_SOURCES} src/main.c)

# 说明
# shell终端获取上级目录：$(dirname $(pwd))

else()
cmake_minimum_required(VERSION 3.8.2)
project("dtls")

include_directories(./ $ENV{MBEDTLS_BASE}/include)
aux_source_directory($ENV{MBEDTLS_BASE}/library MBEDTLS_SOURCES)

set(SOURCES 
	${CMAKE_CURRENT_LIST_DIR}/src/main.c 
	${MBEDTLS_SOURCES})

add_executable(tls ${SOURCES})

endif()