import os
import random
import socket
from scapy.all import *

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('', 12000))

hostname = "10.0.0.100"
response = os.system("ping -c 1 " + hostname + " >> /dev/null &")

ethernet_list = get_if_list()

var = b' No Server'
for l in ethernet_list:
    if "Server1" in l:
        var = b"Reply from Server 1"

    if "Server2" in l:
        var = b"Reply from Server 2"

    if "Server3" in l:
        var = b"Reply from Server 3"


print("Starting Socket")
while True:
    rand = random.randint(0, 10)
    message, address = server_socket.recvfrom(1024)
    print( "Received connection from Client = %s" % address[0])
    message = message.upper()
    message = var
    server_socket.sendto(message, address)
