#!/usr/bin/python
# -*- coding: utf-8 -*-
 
# The modules required
import sys
import socket

'''
This is a template that can be used in order to get started. 
It takes 3 commandline arguments and calls function send_and_receive_tcp.
in haapa7 you can execute this file with the command: 
python3 CourseWorkTemplate.py <ip> <port> <message> 

Functions send_and_receive_tcp contains some comments.
If you implement what the comments ask for you should be able to create 
a functioning TCP part of the course work with little hassle.  

''' 
 
def send_and_receive_tcp(address, port, message):
    print("You gave arguments: {} {} {}".format(address, port, message))
    # create TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect socket to given address and port
    s.connect((address, port))
    # python3 sendall() requires bytes like object. encode the message with str.encode() command
    encoded_msg = str.encode(message)
    # send given message to socket
    s.sendall(encoded_msg)
    # receive data from socket
    r_data = s.recv(1024)
    # data you received is in bytes format. turn it to string with .decode() command
    r_msg = r_data.decode()
    # print received data
    print(r_msg)
    # close the socket
    s.close()
    # Get your CID, UDP port and encryption key from the message
    
    # Continue to UDP messaging. You might want to give the function some other parameters like the above mentioned cid and port.
    send_and_receive_udp(address, port, CID)
    return
 
 
def send_and_receive_udp(address, port, CID, enc_key):
    # Create UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind socket
    sock.bind((address, port))
    # Send data to server
    message = "First message"
    encoded_msg = str.encode(message)
    s.sendall(encoded_msg, (address, port))
    r_data = s.recv(1024)
    r_msg = r_data.decode()
    while True:
        data, addr = s.recvfrom(1024)
        print("received message: %s" % data)
        # Tähän viestin kääntö ja takaisinlähetys
    return
 
 
def main():
    USAGE = 'usage: %s <server address> <server port> <message>' % sys.argv[0]
 
    try:
        # Get the server address, port and message from command line arguments
        server_address = str(sys.argv[1])
        server_tcpport = int(sys.argv[2])
        message = str(sys.argv[3])
    except IndexError:
        print("Index Error")
    except ValueError:
        print("Value Error")
    # Print usage instructions and exit if we didn't get proper arguments
        sys.exit(USAGE)
 
    send_and_receive_tcp(server_address, server_tcpport, message)
 
 
if __name__ == '__main__':
    # Call the main function when this script is executed
    main()





import socket

HOST = "195.148.20.105"  # The server's hostname or IP address
PORT = 10000  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b"Hello, world")
    data = s.recv(1024)

print(f"Received {data!r}")
