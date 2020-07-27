#!/bin/bash
openssl s_server -psk 000102030405060708090A0B0C0D0E0F -cipher TLS13-AES-256-GCM-SHA384 -nocert -accept 2020