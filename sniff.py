import socket
import struct

def parse_ip_header(data):
    header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version = header[0] >> 4
    ihl = header[0] & 0xF
    ttl = header[5]
    protocol = header[6]
    src_ip = socket.inet_ntoa(header[8])
    dst_ip = socket.inet_ntoa(header[9])
    return version, ihl, ttl, protocol, src_ip, dst_ip

def parse_tcp_header(data):
    header = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = header[0]
    dst_port = header[1]
    seq_num = header[2]
    ack_num = header[3]
    flags = header[5]
    return src_port, dst_port, seq_num, ack_num, flags

def sniff_packets(interface, num_packets):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind((interface, 0))
        print(f"Sniffing packets on interface {interface}...")
        for _ in range(num_packets):
            data, _ = sock.recvfrom(65535)
            ip_version, ip_ihl, ip_ttl, ip_protocol, src_ip, dst_ip = parse_ip_header(data[14:])
            if ip_protocol == 6:  # TCP protocol
                src_port, dst_port, _, _, flags = parse_tcp_header(data[14 + (ip_ihl * 4):])
                print(f"Source IP: {src_ip}, Source Port: {src_port}")
                print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")
                print(f"Flags: {flags}")
                print(f"Payload: {data[14 + (ip_ihl * 4) + 20:]}")
                print("=" * 50)

def main():
    interface = "eth0"  # Change this to your network interface (e.g., "eth0", "wlan0")
    num_packets = 10  # Number of packets to capture
    sniff_packets(interface, num_packets)

if __name__ == "__main__":
    main()
