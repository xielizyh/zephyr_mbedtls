#!/bin/bash
sudo openssl s_server --state -cert srv_cert.pem -key srv_privkey.pem -CAfile ca_cert.pem -port 442 -cipher ECDHE-ECDSA-AES256-GCM-SHA384 -WWW ./