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
        data += b'\x00'  # Pad to make even length

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]  # Combine two bytes into one word
        checksum += word

    checksum = (checksum >> 16) + (checksum & 0xffff)  # Add high 16 bits to low 16 bits
    checksum += (checksum >> 16)  # Add carry

    return ~checksum & 0xffff  # One's complement and mask to 16 bits


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
    # Create header with a zero checksum
    header = struct.pack('!BBHHH', icmp_type, code, chk_sum, identifier, sequence)
    data = os.urandom(48)  # Random payload of 48 bytes

    # Calculate the checksum on the header and data
    chk_sum = checksum(header + data)
    # Recreate the header with the correct checksum
    header = struct.pack('!BBHHH', icmp_type, code, chk_sum, identifier, sequence)

    return header + data  # Return the full packet


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
        sock.sendto(packet, (target_ip, 0))  # Send packet to target IP
    except socket.error as e:
        print(f"Error sending packet: {e}")


def main() -> None:
    """
    Main logic of sending ICMP packets to trace route to a target
    :return: None
    """
    target = "google.com"  # Target domain
    target_ip = resolve_target(target)  # Resolve domain to IP
    if target_ip is None:
        return

    sock = create_socket()  # Create raw socket
    if sock is None:
        return

    identifier = os.getpid() & 0xFFFF  # Use process ID as identifier
    sequence = 1  # Initial sequence number
    packet = create_icmp_packet(identifier, sequence)  # Create ICMP packet

    send_icmp_packet(sock, target_ip, packet)  # Send ICMP packet

    sock.close()  # Close socket


if __name__ == "__main__":
    main()