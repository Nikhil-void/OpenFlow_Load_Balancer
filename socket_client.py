import time
import socket

for pings in range(3):
    time.sleep(2)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(3.0)
    message = b'test'
    addr = ("10.0.0.100", 12000)

    start = time.time()
    client_socket.sendto(message, addr)
    try:
        data, server = client_socket.recvfrom(1024)
        end = time.time()
        elapsed = end - start
        print(data)

    except socket.timeout:
        print('REQUEST TIMED OUT')
