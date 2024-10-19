import socket
import struct
import time
import os
import sys
import statistics
import curses

# Dictionary to store RTT data for each hop
rtt_data = {}
# Dictionary to store the number of sent packets for each TTL
sent_packets = {}
# Dictionary to store the number of received packets for each TTL
received_packets = {}


def resolve_target(target: str) -> str:
    """
    Resolve the target domain to an IP address
    :param target: The domain name to resolve
    :return: The resolved IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"Error resolving domain {target}: {e}")
        return None


def checksum(source_string: bytes) -> int:
    """
    Calculate the checksum for the ICMP header and data
    :param source_string: The data to calculate the checksum for
    :return: The calculated checksum
    """
    if len(source_string) % 2 == 1:
        source_string += b'\x00'
    checksum = 0
    for i in range(0, len(source_string), 2):
        word = (source_string[i] << 8) + source_string[i + 1]
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    return ~checksum & 0xffff


def create_icmp_packet(identifier: int, sequence_number: int) -> bytes:
    """
    Create an ICMP packet with the specified identifier and sequence number
    :param identifier: The identifier for the ICMP packet
    :param sequence_number: The sequence number for the ICMP packet
    :return: The created ICMP packet
    """
    icmp_type = 8  # ICMP Echo Request
    code = 0  # Code for ICMP Echo Request
    chk_sum = 0  # Initial checksum value
    header = struct.pack('!BBHHH', icmp_type, code, chk_sum, identifier, sequence_number)
    data = os.urandom(48)  # Random payload data
    chk_sum = checksum(header + data)  # Calculate checksum
    header = struct.pack('!BBHHH', icmp_type, code, chk_sum, identifier, sequence_number)
    return header + data


def create_socket() -> socket:
    """
    Create a raw socket for sending ICMP packets
    :return: The created raw socket or None if creation fails
    """
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as e:
        print(f"Error creating socket: {e}")
        return None


def send_icmp_packet(icmp_socket: socket.socket, target_ip: str, packet: bytes, ttl: int) -> float:
    """
    Send an ICMP packet to the target IP with the specified TTL
    :param icmp_socket: The socket to send the packet through
    :param target_ip: The target IP address
    :param packet: The ICMP packet to send
    :param ttl: The Time-To-Live value for the packet
    :return: The time the packet was sent or None if sending fails
    """
    try:
        icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        send_time = time.time()
        icmp_socket.sendto(packet, (target_ip, 0))
        return send_time
    except socket.error as e:
        print(f"Error sending packet: {e}")
        return None


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


def receive_icmp_reply(icmp_socket: socket.socket, target_ip: str, send_time: float) -> tuple:
    """
    Receive an ICMP reply and calculate the round-trip time (RTT)
    :param icmp_socket: The socket to receive the reply through
    :param target_ip: The target IP address
    :param send_time: The time the packet was sent
    :return: A tuple containing a boolean indicating if the reply was received, the RTT, and the reply IP address
    """
    try:
        icmp_socket.settimeout(2)
        data, addr = icmp_socket.recvfrom(1024)
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
    last_rtt = rtt_data[ttl][-1]
    min_rtt = min(rtt_data[ttl])
    max_rtt = max(rtt_data[ttl])
    avg_rtt = statistics.mean(rtt_data[ttl])
    stdev_rtt = statistics.stdev(rtt_data[ttl]) if len(rtt_data[ttl]) > 1 else 0
    return last_rtt, min_rtt, max_rtt, avg_rtt, stdev_rtt


def calculate_loss_percentage(ttl: int) -> float:
    """
    Calculate the packet loss percentage for a given TTL
    :param ttl: The Time-To-Live value
    :return: The packet loss percentage
    """
    sent = sent_packets.get(ttl, 0)
    received = received_packets.get(ttl, 0)
    if sent == 0:
        return 0.0
    return ((sent - received) / sent) * 100


def main(stdscr: curses.window) -> None:
    """
    Main function to perform traceroute-like functionality with curses for display
    :param stdscr: The curses window object
    :return: None
    """
    if len(sys.argv) != 2:
        print("Usage: sudo python mtr4.py <target_domain>")
        return

    target = sys.argv[1]
    target_ip = resolve_target(target)
    if target_ip is None:
        return

    # Clear the screen and print the header
    stdscr.clear()
    stdscr.addstr(0, 0, f"Target {target} resolved to {target_ip}")
    stdscr.addstr(1, 0,
                  f"{'TTL':<5}{'Host':<79}{'Last':<14} {'Min':<13} {'Avg':<13} {'Max':<11} {'StDev':<11} {'Loss %':<10}")
    stdscr.addstr(2, 0, "-" * 158)
    stdscr.refresh()

    sock = create_socket()
    if sock is None:
        return

    identifier = os.getpid() & 0xFFFF
    sequence_number = 1

    ttl = 2

    while True:
        packet = create_icmp_packet(identifier, sequence_number)
        send_time = send_icmp_packet(sock, target_ip, packet, ttl)
        if send_time is None:
            break

        if ttl not in sent_packets:
            sent_packets[ttl] = 0
        sent_packets[ttl] += 1

        received, rtt, reply_ip = receive_icmp_reply(sock, target_ip, send_time)

        if received:
            if ttl not in received_packets:
                received_packets[ttl] = 0
            received_packets[ttl] += 1

            last_rtt, min_rtt, max_rtt, avg_rtt, stdev_rtt = update_rtt_stats(ttl, rtt)
            loss_percentage = calculate_loss_percentage(ttl)
            stdscr.addstr(ttl + 1, 0,
                          f"{ttl:<5}{reply_ip:<70}{last_rtt:>10.2f} ms {min_rtt:>10.2f} ms "
                          f"{avg_rtt:>10.2f} ms {max_rtt:>10.2f} ms {stdev_rtt:>10.2f} ms {loss_percentage:>10.2f} % (Reached destination)")
            stdscr.refresh()
            break

        if reply_ip:
            hostname = resolve_ip_to_hostname(reply_ip)
            if ttl not in received_packets:
                received_packets[ttl] = 0
            received_packets[ttl] += 1

            last_rtt, min_rtt, max_rtt, avg_rtt, stdev_rtt = update_rtt_stats(ttl, rtt)
            loss_percentage = calculate_loss_percentage(ttl)
            stdscr.addstr(ttl + 1, 0,
                          f"{ttl:<5}{hostname:<70}{last_rtt:>10.2f} ms {min_rtt:>10.2f} ms "
                          f"{avg_rtt:>10.2f} ms {max_rtt:>10.2f} ms {stdev_rtt:>10.2f} ms {loss_percentage:>10.2f} %")
        else:
            loss_percentage = 100.0
            stdscr.addstr(ttl + 1, 0,
                          f"{ttl:<5}{'*':<70}{'*':>10} ms {'*':>10} ms {'*':>10} ms {'*':>10} ms {'*':>10} ms {loss_percentage:>10.2f} %")
        stdscr.refresh()
        ttl += 1
        sequence_number += 1

    sock.close()
    stdscr.addstr(ttl + 2, 0, "Press any key to exit...")
    stdscr.refresh()
    stdscr.getch()


if __name__ == "__main__":
    curses.wrapper(main)
