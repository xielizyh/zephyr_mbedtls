### TLS服务器和客户端通信

利用Openssl测试TLS服务器和客户端通信

# 构建TLS服务器

`cert.sh`为利用mbedtls工具编写的证书生成脚本

# 启动s_server

执行./server.sh脚本或者
sudo openssl s_server --state -cert srv_cert.pem -key srv_privkey.pem -CAfile ca_cert.pem -port 442 -cipher ECDHE-ECDSA-AES256-GCM-SHA384 -WWW ./

# 启动s_client

执行./client.sh脚本或者
sudo openssl s_client --connect localhost:442 -CAfile ca_cert.pem

# s_server&client.png

通信过程截图

# 参考

《mbedtls_开发实战》第14章