#!/usr/bin/python
# -*- coding: utf-8 -*-
 
# The modules required
import sys
import socket
import xml.etree.ElementTree as ET

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
    r_data = s.recv(64)
    # data you received is in bytes format. turn it to string with .decode() command
    r_msg = r_data.decode()
    # print received data
    print(r_msg)
    # close the socket
    s.close()
    # Get your CID, UDP port and encryption key from the message
    root = ET.fromstring(r_msg)
    # Print child nodes of root
    for child in root:
        print(child.tag, child.attrib)
    # Continue to UDP messaging. You might want to give the function some other parameters like the above mentioned cid and port.
    send_and_receive_udp(address, udp_port, CID)
    return
 
 
def send_and_receive_udp(address, port, CID, enc_key):
    # Create UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind socket
    s.bind((address, port))
    # Send data to server
    init_message = "Hello from {}".format(CID)
    size_of_message = sys.getsizeof(message)
    # Split init message before sending if needed
    packets = split_message(init_message)


    # Sending messages
    for i in range(0, len(packets)):
        # Check how many bytes left of the message
        send_and_receive_udp.byte_counter += sys.getsizeof(packets[i])
        bytes_left = size_of_message - byte_counter
        length_of_msg = sys.getsizeof(packets[i])
        # encode
        encoded_msg = str.encode(packet)
        # encrypt and add parity bit
        encrypted_msg = add_parity_bit_to_message(en_de_crypt(encoded_msg, enc_key))
        # ACK = True because this is the first TCP message
        # otherwise set by checking parity
        encoded_binary_msg = struct.pack(‘!8s??HH128s’, CID, True, False, bytes_left, length_of_msg, encrypted_msg)
        s.sendto(encoded_binary_msg, (address, port))


    # Receiving messages
    while True:
        data, addr = s.recvfrom(64)
        r_msg = r_data.decode()
        if check_parity(r_msg):
            decrypted_r_msg = en_de_crypt(r_msg, enc_key)
        else:
            # Pyydä uudelleenlähetystä
        print("received message: %s" % data)
        # Tähän viestin kääntö ja takaisinlähetys
    return
# Initialize function attribute
send_and_receive_udp.byte_counter = 0
    
# Parity must be added after encryption and read before decryption!

def get_parity(n):
    while n > 1:
        n = (n >> 1) ^ (n & 1)
    return n

def add_parity_bit(n):
    n <<= 1
    n += get_parity(n)
    return n

def check_parity(n):
    read_parity_bit = (n & 1)
    n >>= 1
    if get_parity(n) == read_parity_bit:
        print("parity check ok!")
        return 1
    else:
        print("parity check failed!")
        return 0

def en_de_crypt(message, key):
    return message ^ key

def split_message(message):
    packets = []
    size_of_message = sys.getsizeof(message)
    if size_of_message < 65:
        # no need for splitting
        packets.append(message)
        return packets
    else:
        # splitting needed
        if (size_of_message % 64) != 0:
            number_of_packets = int(size_of_message/64) + 1
        else:
            number_of_packets = size_of_message/64
        # construct packets
        for packet in range(0, number_of_packets):
            a_packet = message[packet*64:64+packet*64]
            packets.append(a_packet)
        return packets

def add_parity_bit_to_message(message):
    for char in message:
        add_parity_bit(char) 
    return message

def reverse_word_order(string):
    word_list = string.split()
    for i in range(0, int(len(word_list)/2)):
        temp = word_list[-1-i]
        word_list[-1-i] = word_list[i]
        word_list[i] = temp
    reversed_string = ""
    for word in word_list:
        reversed_string += word
        if !(word_list.index(word) == (len(word_list) - 1)):
            reversed_string += " "
    return reversed_string

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
