import os
import socket
import struct


def resolve_target(domain: str) -> str:
    """
    Resolve the target domain to an IP address
    :param domain: str
    :return: str
    """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        print(f"Error resolving domain {domain}: {e}")
        return None


def checksum(data: bytes) -> int:
    """
    Calculate the ICMP header checksum
    :param data: bytes
    :return: int
    """
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
    """
    Create an ICMP packet
    :param identifier: int
    :param sequence: int
    :return: bytes
    """
    icmp_type = 8  # ICMP Echo Request
    code = 0
    chk_sum = 0
    header = struct.pack('!BBHHH', icmp_type, code, chk_sum, identifier, sequence)
    data = os.urandom(48)  # Random payload of 48 bytes

    # Calculate the checksum on the header and data
    chk_sum = checksum(header + data)
    header = struct.pack('!BBHHH', icmp_type, code, chk_sum, identifier, sequence)

    return header + data


def create_socket() -> socket.socket:
    """
    Create a raw socket
    :return: socket.socket
    """
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as e:
        print(f"Error creating socket: {e}")
        return None


def send_icmp_packet(sock: socket.socket, target_ip: str, packet: bytes) -> None:
    """
    Send an ICMP packet
    :param sock: socket.socket
    :param target_ip: str
    :param packet: bytes
    :return: None
    """
    try:
        sock.sendto(packet, (target_ip, 0))
    except socket.error as e:
        print(f"Error sending packet: {e}")
