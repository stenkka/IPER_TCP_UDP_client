#!/usr/bin/python3
# -*- coding: utf-8 -*-
 
# Modules
import sys
import struct
import secrets
import socket

# Global variables
key_counter_server = 0
key_counter_client = 0

def send_and_receive_tcp(address, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # Create TCP socket
    print("CONNECTING TO: " + str(address) + " " + str(port))
    s.connect((address, port))
    key_list = gen_key(32, 20)
    key_list_from_server = []
    message_static = "HELLO ENC MUL PAR\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}"\
        "\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}\r\n{}"\
        "\r\n.\r\n".format(
        key_list[0], key_list[1], key_list[2], key_list[3],key_list[4], key_list[5], 
        key_list[6], key_list[7], key_list[8], key_list[9], key_list[10], key_list[11], 
        key_list[12], key_list[13], key_list[14], key_list[15], key_list[16], key_list[17], 
        key_list[18], key_list[19])
    encoded_msg = str.encode(message_static)
    print("SENDING TO SERVER: " + message_static)
    s.sendall(encoded_msg)
    r_data = s.recv(5120)
    r_msg = r_data.decode('utf8')
    print("FROM SERVER: " + r_msg)
    s.close()
    cid = r_msg.split()[1]
    udp_port = int(r_msg.split()[2])
    for i in range(3, 23):
        key_list_from_server.append(r_msg.split()[i])
    send_and_receive_udp(address, udp_port, cid, key_list_from_server, key_list)
    return
 
def send_and_receive_udp(address, port, cid, enc_keys_from_server, enc_keys):
    # variable initializations
    global key_counter_client, key_counter_server
    message_entire = ""
    list_of_words_in_message = []
    send_again_flag = 0

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    # Create UDP socket
    init_message = "Hello from {}".format(cid)
    pack_and_send_udp(s, address, port, init_message, enc_keys, cid)    # Pack & send hello-message
    print("\nSTARTING TO RECEIVE\n")
    while True:
        data_r, addr = s.recvfrom(256)
        key_counter_client += 1
        print("KEY_COUNTER_CLIENT: " + str(key_counter_client) + "\n")
        cid_r, ack_r, eom_r, bytes_left_r, length_of_packet_r, encrypted_msg_r = struct.unpack(
            '!8s??HH128s', data_r)  # Unpack
        encrypted_msg_r = encrypted_msg_r.decode()[:length_of_packet_r]  # Decode & remove trailing zeros
        if ((key_counter_client < 21) and (not eom_r)):
            if not (check_parity_of_message(encrypted_msg_r)):
                send_again_flag = 1
            encrypted_msg_r = remove_parity_bit_from_message(encrypted_msg_r)   # Remove parity bit
            decrypted_msg_r = crypt(
            encrypted_msg_r, enc_keys_from_server[key_counter_client-1], len(encrypted_msg_r)) # Decrypt
        elif ((key_counter_client > 20) and (not eom_r)):
            decrypted_msg_r = encrypted_msg_r   # Switch to plaintext
        else:
            # Program done
            print(encrypted_msg_r)
            return

        print("INCOMING MESSAGE: " + decrypted_msg_r)
        # Message reverse operation and resend
        if (not send_again_flag):
            message_entire += decrypted_msg_r
        if ((bytes_left_r == 0) and (send_again_flag)):
            print("\nREQUESTING RESEND\n")
            encoded_binary_msg = struct.pack(
                '!8s??HH128s', bytes(cid, "utf-8"), False, False, 0, 10, bytes(
                "Send again", "utf-8"))
            s.sendto(encoded_binary_msg, (address, port))
            send_again_flag = 0
        elif (bytes_left_r == 0):
            print("Now sending reversed")
            print("NON-REVERSED: " + message_entire + "\n")
            reversed_message = reverse_word_order(message_entire)
            print("REVERSED: " + reversed_message + "\n")
            pack_and_send_udp(s, address, port, reversed_message, enc_keys, cid)
            message_entire = ""
            list_of_words_in_message = []
    return
    
def pack_and_send_udp(s, address, port, message, encryption_keys, cid):
    global key_counter_server
    byte_counter = 0
    size_of_message = len(message)
    # Split init message before sending if needed
    packets = split_message(message)
    # --- Sending messages ---
    for i in range(0, len(packets)):
        print("SENDING: " + packets[i])
        # Check how many bytes left of the message
        byte_counter += len(packets[i])
        bytes_left = size_of_message - byte_counter
        print("BYTES LEFT: " + str(bytes_left))
        # encrypt and add parity bit
        key_counter_server += 1
        if (key_counter_server < 21):
            encrypted_msg = crypt(packets[i], encryption_keys[key_counter_server-1], len(packets[i]))
            encrypted_msg = add_parity_bit_to_message(encrypted_msg)
        else:
            encrypted_msg = packets[i]
        encoded_binary_msg = struct.pack(
            '!8s??HH128s', cid.encode(), True, False, bytes_left, len(packets[i]), encrypted_msg.encode())
        print("SENDING PACKED MESSAGE: " + str(encoded_binary_msg))
        s.sendto(encoded_binary_msg, (address, port))
def gen_key(size, key_amount):
    keys = []
    for i in range(0, key_amount):
        keys.append(secrets.token_hex(size))
    return keys
def get_parity(n):
    while n > 1:
        n = (n >> 1) ^ (n & 1)
    return n

def add_parity_bit(n):
    n = ord(n)
    n <<= 1
    pbit = get_parity(n)
    n += pbit
    return chr(n)

def remove_parity_bit_from_message(message):
    list_of_chars = []
    for n in message:
        n = ord(n)
        n >>= 1
        list_of_chars.append(chr(n))
    return ''.join(list_of_chars)

def check_parity(n):
    n = ord(n)
    read_parity_bit = (n & 1)
    n >>= 1
    if get_parity(n) == read_parity_bit:
        return 1
    else:
        print("\nPARITY CHECK FAILED!\n")
        return 0

def check_parity_of_message(message):
    for character in message:
        if not check_parity(character):
            return 0
    return 1 

def crypt(message, key, length_of_message):
    list_of_chars = []
    print("LEN OF MSG: " + str(length_of_message))
    print("LEN OF KEY: " + str(len(key)))
    for i in range(0,length_of_message):
        list_of_chars.append(chr(ord(message[i]) ^ ord(key[i])))
    return ''.join(list_of_chars)
def split_message(message):
    packets = []
    size_of_message = len(message)
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
        for i in range(0, int(number_of_packets)):
            packet = message[i*64:64+i*64]
            packets.append(packet)
        return packets

def add_parity_bit_to_message(message):
    list_of_chars = []
    for character in message:
        list_of_chars.append(add_parity_bit(character))
    return ''.join(list_of_chars)

def reverse_word_order(string):
    word_list = string.split()
    for i in range(0, int(len(word_list)/2)):
        temp = word_list[-1-i]
        word_list[-1-i] = word_list[i]
        word_list[i] = temp
    return ' '.join(word_list)

def main():
    USAGE = 'usage: %s <server address> <server port>' % sys.argv[0]
 
    try:
        # Get the server address, port from command line arguments
        server_address = str(sys.argv[1])
        server_tcpport = int(sys.argv[2])
    except IndexError:
        print("Index Error")
    except ValueError:
        print("Value Error")
    # Print usage instructions and exit if we didn't get proper arguments
        sys.exit(USAGE)
 
    send_and_receive_tcp(server_address, server_tcpport)
 
 
if __name__ == '__main__':
    # Call the main function when this script is executed
    main()