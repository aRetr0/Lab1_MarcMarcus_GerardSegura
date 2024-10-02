import os
import socket
import struct
import sys
import time


def resolve_target(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        print(f"Error resolving domain {domain}: {e}")
        return None


def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)

    return ~checksum & 0xffff


def create_icmp_packet(identifier: int, sequence: int) -> bytes:
    icmp_type = 8
    code = 0
    chk_sum = 0
    header = struct.pack('!BBHHH', icmp_type, code, chk_sum, identifier, sequence)
    data = os.urandom(48)

    chk_sum = checksum(header + data)
    header = struct.pack('!BBHHH', icmp_type, code, chk_sum, identifier, sequence)

    return header + data


def create_socket() -> socket.socket:
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as e:
        print(f"Error creating socket: {e}")
        return None


def send_icmp_packet(sock: socket.socket, target_ip: str, packet: bytes, ttl: int) -> float:
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        send_time = time.time()
        sock.sendto(packet, (target_ip, 0))
        return send_time
    except socket.error as e:
        print(f"Error sending packet: {e}")
        return None


def receive_icmp_reply(sock: socket.socket, target_ip: str, ttl: int, send_time: float) -> (bool, float, str):
    try:
        sock.settimeout(2)
        data, addr = sock.recvfrom(1024)
        receive_time = time.time()
        rtt = (receive_time - send_time) * 1000
        if addr[0] == target_ip:
            return True, rtt, addr[0]
        else:
            return False, rtt, addr[0]
    except socket.timeout:
        return False, None, None
    except socket.error as e:
        print(f"Error receiving reply: {e}")
        return False, None, None


def resolve_ip_to_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: sudo python mtr1.py <target_domain>")
        return

    target = sys.argv[1]
    target_ip = resolve_target(target)
    if target_ip is None:
        return

    print(f"Target {target} resolved to {target_ip}")

    sock = create_socket()
    if sock is None:
        return

    identifier = os.getpid() & 0xFFFF
    sequence = 1

    print(f"{'Hop':<5}{'IP/Hostname':<60}{'RTT':<20}")
    print("-" * 85)

    ttl = 1
    while True:
        packet = create_icmp_packet(identifier, sequence)
        send_time = send_icmp_packet(sock, target_ip, packet, ttl)
        if send_time is None:
            break
        received, rtt, reply_ip = receive_icmp_reply(sock, target_ip, ttl, send_time)
        if received:
            print(f"{ttl:<5}{reply_ip:<60}{f'{rtt:.2f} ms (Reached destination)':<20}")
            break
        if reply_ip:
            hostname = resolve_ip_to_hostname(reply_ip)
            print(f"{ttl:<5}{hostname:<60}{f'{rtt:.2f} ms':<20}")
        else:
            print(f"{ttl:<5}{'*':<60}{'Request timed out.':<20}")
        ttl += 1

    sock.close()


if __name__ == "__main__":
    main()