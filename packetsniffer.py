import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main(format_multi_line, ipv4_packet, acknowledgement, src_port, dest_port, sequence,
         flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin):
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind(('', 0))

    while True:
        raw_data = conn.recv(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # 8 for IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet: ')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}. '.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}, '.format(proto, src, target))

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}, '.format(icmp_type, code, checksum))
                print(format_multi_line(DATA_TAB_3, data))

            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, '.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}, '.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, FIN: {}, '.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source PortL {}, Destination Port: {}, Length: {} '.format(src_port, dest_port, length))

            # Other
            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print('Data:')
            print(format_multi_line(DATA_TAB_2, data))


# Unpack Ethernet
def ethernet_frame(data):  # ethernet frame returns, destination, source, ethernet protocol and payload (4 chunks)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])  # first 14 bytes that follow the sniff
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[:14]


# return properly mac address (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str: map[str] = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# unpacks ipv4 packets
def ipv4_frame(data, proto):
    version_header_length = data[0]
    version = version_header_length >> 4  # shift to only get the version number of the ipv4 frame
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s', data[:20])
    return version, ttl, header_length, proto, ipv4(src), ipv4(target), data[header_length:]


# returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


# unpacks icmp packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[4])
    return icmp_type, code, checksum, data[4:]


# unpacks tcp segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[
                                                                                                                       :offset]
# unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Formats multi-line data
def format_multi(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        hex_string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
        formatted_string = '\n'.join([prefix + line for line in textwrap.wrap(hex_string, size)])
        return formatted_string
    else:
        return prefix + string

# Example values, replace with your actual data
src_port_value = 1234
dest_port_value = 5678
sequence_value = 9876
acknowledgement_value = 5432
flag_urg_value = 1
flag_ack_value = 0
flag_psh_value = 1
flag_rst_value = 0
flag_syn_value = 1
flag_fin_value = 0


main(format_multi, ipv4_frame, icmp_packet, src_port_value, dest_port_value, sequence_value,
     flag_urg_value, flag_ack_value, flag_psh_value, flag_rst_value, flag_syn_value, flag_fin_value)

