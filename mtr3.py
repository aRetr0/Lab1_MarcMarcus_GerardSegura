import os
import socket
import statistics
import struct
import sys
import time

# Define a dictionary to store RTT data for each hop
rtt_data = {}


def resolve_target(domain: str) -> str:
    """
    Resolve the target domain to an IP address
    :param domain: The domain name to resolve
    :return: The resolved IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        print(f"Error resolving domain {domain}: {e}")
        return None


def checksum(data: bytes) -> int:
    """
    Calculate the checksum for the ICMP header and data
    :param data: The data to calculate the checksum for
    :return: The calculated checksum
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
    Create an ICMP packet with the specified identifier and sequence number
    :param identifier: The identifier for the ICMP packet
    :param sequence: The sequence number for the ICMP packet
    :return: The created ICMP packet
    """
    icmp_type = 8  # ICMP Echo Request
    code = 0  # Code for ICMP Echo Request
    chk_sum = 0  # Initial checksum value
    # Pack the header with initial checksum
    header = struct.pack('!BBHHH', icmp_type, code, chk_sum, identifier, sequence)
    # Generate a random payload of 48 bytes
    data = os.urandom(48)

    # Calculate the checksum for the header and data
    chk_sum = checksum(header + data)
    # Recreate the header with the correct checksum
    header = struct.pack('!BBHHH', icmp_type, code, chk_sum, identifier, sequence)

    # Return the complete ICMP packet
    return header + data


def create_socket() -> socket.socket:
    """
    Create a raw socket for sending ICMP packets
    :return: The created raw socket or None if creation fails
    """
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as e:
        print(f"Error creating socket: {e}")
        return None


def send_icmp_packet(sock: socket.socket, target_ip: str, packet: bytes, ttl: int) -> float:
    """
    Send an ICMP packet to the target IP with the specified TTL
    :param sock: The socket to send the packet through
    :param target_ip: The target IP address
    :param packet: The ICMP packet to send
    :param ttl: The Time-To-Live value for the packet
    :return: The time the packet was sent or None if sending fails
    """
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        send_time = time.time()
        sock.sendto(packet, (target_ip, 0))
        return send_time
    except socket.error as e:
        print(f"Error sending packet: {e}")
        return None


def receive_icmp_reply(sock: socket.socket, target_ip: str, ttl: int, send_time: float) -> (bool, float, str):
    """
    Receive an ICMP reply
    :param sock: The socket to receive the reply through
    :param target_ip: The target IP address
    :param ttl: The Time-To-Live value for the packet
    :param send_time: The time the packet was sent
    :return: A tuple containing a boolean indicating if the reply was received, the RTT, and the reply IP address
    """
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
    """
    Resolve an IP address to a hostname
    :param ip: The IP address to resolve
    :return: The resolved hostname or the IP address if resolution fails
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip


def update_rtt_stats(ttl: int, rtt: float):
    """
    Update the RTT statistics for a given TTL
    :param ttl: The Time-To-Live value
    :param rtt: The round-trip time
    :return: A tuple containing the last RTT, minimum RTT, maximum RTT, average RTT, and standard deviation of RTT
    """
    if ttl not in rtt_data:
        rtt_data[ttl] = []
    rtt_data[ttl].append(rtt)

    # Calculate statistics
    last_rtt = rtt_data[ttl][-1]
    min_rtt = min(rtt_data[ttl])
    max_rtt = max(rtt_data[ttl])
    avg_rtt = statistics.mean(rtt_data[ttl])
    stdev_rtt = statistics.stdev(rtt_data[ttl]) if len(rtt_data[ttl]) > 1 else 0

    return last_rtt, min_rtt, max_rtt, avg_rtt, stdev_rtt


def main() -> None:
    """
    Main logic of sending ICMP packets to trace route to a target
    :return: None
    """
    if os.geteuid() != 0:
        print("This script must be run with sudo or as root.")
        sys.exit(1)

    if len(sys.argv) != 2:
        print("Usage: sudo python mtr3.py <target_domain>")
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

    # Print table header with fixed widths for each column
    print(f"{'Hop':<5}{'IP/Hostname':<70}{'Last':<10}{'Min':<10}{'Max':<10}{'Avg':<10}{'StDev':<10}")
    print("-" * 120)

    ttl = 1
    while True:
        packet = create_icmp_packet(identifier, sequence)
        send_time = send_icmp_packet(sock, target_ip, packet, ttl)
        if send_time is None:
            break
        received, rtt, reply_ip = receive_icmp_reply(sock, target_ip, ttl, send_time)
        if received:
            last_rtt, min_rtt, max_rtt, avg_rtt, stdev_rtt = update_rtt_stats(ttl, rtt)
            print(
                f"{ttl:<5}{reply_ip:<70}{last_rtt:<10.2f}{min_rtt:<10.2f}{max_rtt:<10.2f}{avg_rtt:<10.2f}{stdev_rtt:<10.2f} (Reached destination)")
            break
        if reply_ip:
            hostname = resolve_ip_to_hostname(reply_ip)
            last_rtt, min_rtt, max_rtt, avg_rtt, stdev_rtt = update_rtt_stats(ttl, rtt)
            print(
                f"{ttl:<5}{hostname:<70}{last_rtt:<10.2f}{min_rtt:<10.2f}{max_rtt:<10.2f}{avg_rtt:<10.2f}{stdev_rtt:<10.2f}")
        else:
            print(f"{ttl:<5}{'*':<70}{'Request timed out.':<50}")
        ttl += 1

    sock.close()


if __name__ == "__main__":
    main()
