import socket
from networking.general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP


def main():
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)

        print('\nEthernet Frame:')
        print('\t -' + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))
        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print('\t -' 'IPv4 Packet:')
            print('\t\t -' + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length,
                                                                               ipv4.ttl))
            print('\t\t -' + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print('\t' + 'ICMP Packet:')
                print('\t\t -' + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print('\t\t -' + 'ICMP Data:')
                print(format_multi_line('\t\t\t', icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print('\t -' + 'TCP Segment:')
                print('\t\t -' + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print('\t\t -' + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print('\t\t -' + 'Flags:')
                print('\t\t -' + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print('\t\t\t -' + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print('\t\t' + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print('\t\t\t' + str(line))
                        except Exception:
                            print(format_multi_line('\t\t\t', tcp.data))

                    else:
                        print('\t\t -' + 'TCP Data:')
                        print(format_multi_line('\t\t\t', tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print('\t\t' + 'UDP Segment:')
                print('\t\t' + 'Source Port: {}, Destination Port: {}, Length:{}'.format(udp.src_port, udp.dest_port,
                                                                                         udp.size))

            # Other IPv4
            else:
                print('\t -' + 'Other IPv4 Data:')
                print(format_multi_line('\t\t', ipv4.data))

        else:
            print('Ethernet Data:')
            print(format_multi_line('\t', eth.data))
    pcap.close()


main()


# Class Ethernet imported to main class sniffer through networking

import socket
import struct
from general import *


class Ethernet:

    def __init__(self, raw_data):
        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]


# Class HTTP imported to main class sniffer through networking

class HTTP:

    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data

# Class ICMP imported to main class sniffer through networking

import struct


class ICMP:

    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]


# Class IPv4 imported to main class sniffer through networking
import struct


class IPv4:

    def __init__(self, raw_data):
        version_header_length = raw_data[0]

        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4(src)
        self.target = self.ipv4(target)
        self.data = raw_data[self.header_length:]

    # Returns properly formatted IPv4 address
    def ipv4(self, addr):
        return '.'.join(map(str, addr))

# Class Pcap imported to main class sniffer through networking

import struct
import time


class Pcap:
    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()


# Class TCP imported to main class sniffer through networking

import struct


class TCP:
    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(
            '! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = raw_data[offset:]

# Class UDP imported to main class sniffer through networking

import struct


class UDP:
    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', raw_data[:8])
        self.data = raw_data[8:]

# Class General imported to main class sniffer through networking

import textwrap

# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



