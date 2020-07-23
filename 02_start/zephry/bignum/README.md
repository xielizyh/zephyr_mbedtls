# 执行步骤

* mkdir -p build && cd build
* cmake -DBOARD=native_posix
* make -j24
* make run

# 未解决@TODO
`mbedtls_config.h`配置文件未生效