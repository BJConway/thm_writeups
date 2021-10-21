#!/usr/bin/env python3

import socket

IP = "10.10.154.171"

def banner_grab(ip: str, port: int) -> None:
    s = socket.socket()
    s.settimeout(3)
    s.connect((ip, port))
    try:
        print(s.recv(1024))
    except socket.timeout:
        print('timeout...')

with open('nmap-out.txt') as f:
    for l in f.readlines():
        # I manually removed the header etc. from the nmap output to make parsing easier
        port = int(l.split('/')[0])
        print(port, end='\t')
        banner_grab(IP, port)

