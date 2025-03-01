#!/usr/bin/python3
import random
import socket
import subprocess, sys
import trace_base
import json

port = 34023

fragment_sz = 1000

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('', 34023))


def fragment(str1, fr_sz):
    num_fr_f = len(str1)/fr_sz
    num_fr = int(num_fr_f)
    ii = 0
    
    if num_fr_f > num_fr:
      packet = [str(num_fr + 1)]
    else:
      packet = [str(num_fr)]

    for ii in range(num_fr):
      pos = ii * fr_sz
      packet.append(str1[pos : pos + fr_sz])
    if num_fr_f > num_fr:
      pos = num_fr * fr_sz
      packet.append(str1[pos :])
    return packet



def execute(commandi, address):

    try:
        result = subprocess.check_output(command, shell = True, executable = "/bin/bash", stderr = subprocess.STDOUT)

    except subprocess.CalledProcessError as cpe:
        result = cpe.output

    finally:
        for line in result.splitlines():
            print(line.decode())
            server_socket.sendto(line, address)


while True:
    message, address = server_socket.recvfrom(1024)
    command = message.decode('utf-8')
    if command == "echo":
        server_socket.sendto(message, address)
        print(command)
        continue
    opts = json.loads(command)
    trs = trace_base.trace_base()
    msg = trs.run_test(opts)
    sz = len(msg)
    fragmented = fragment(msg, fragment_sz)

    for frag in fragmented:
        server_socket.sendto(frag.encode(), address)



