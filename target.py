#!/usr/bin/python3

import socket
import subprocess, sys
import trace_base
import json


fragment_sz = 1000
port = 34023


class queue:
    def __init__(self):
        self.q = []

    def push(self, val):
        self.q.insert(0, val)

    def pop(self):
        return self.q.pop()





class udp_server:
    def __init__(self, sock_port, fragment_sz):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(('', sock_port))
        self.server_socket.settimeout(2.0)
        self.fr_sz = fragment_sz


    def fragment(self, str1):
        num_fr_f = len(str1)/self.fr_sz
        num_fr = int(num_fr_f)
        ii = 0

        if num_fr_f > num_fr:
          packet = [str(num_fr + 1)]
        else:
          packet = [str(num_fr)]

        for ii in range(num_fr):
          pos = ii * self.fr_sz
          packet.append(str1[pos : pos + self.fr_sz])
        if num_fr_f > num_fr:
          pos = num_fr * self.fr_sz
          packet.append(str1[pos :])
        return packet


    def server(self):
        while True:
            try:
                message, address = self.server_socket.recvfrom(self.fr_sz + 24)
                command = message.decode('utf-8')

            except socket.timeout:
                continue

            match command:
                case "echo":
                    self.server_socket.sendto(message, address)
                    print(command)
                    continue

                case "start":
                    self.server_socket.sendto(message, address)
                    try:
                        message, address = self.server_socket.recvfrom(self.fr_sz + 24)
                        command = message.decode('utf-8')
                        opts = json.loads(command)
                        trs = trace_base.trace_base()
                        self.result = trs.run_test(opts)

                    except socket.timeout:
                        continue

                case "data":
                        sz = len(self.result)
                        fragmented = self.fragment(self.result)
                        for frag in fragmented:
                            self.server_socket.sendto(frag.encode(), address)

                case _: #defauld
                        self.server_socket.sendto(message, address)
                        print(f'Wrong command:    {command}')
                        continue


print(f"Kernel tracing version: {trace_base.Version}")

serv = udp_server(port, fragment_sz)
serv.server()

