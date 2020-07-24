#!/bin/sh
openssl s_client -state -connect localhost:4332 -dtls1_2 -cipher PSK-AES128-CCM8 -psk_identity Client_identity -psk 000102030405060708090a0b0c0d0e0f