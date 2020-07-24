#!/bin/sh
openssl s_server -state -nocert -dtls1_2 -port 4432 -cipher PSK-AES128-CCM8 -psk_hint Client_identity -psk 000102030405060708090a0b0c0d0e0f