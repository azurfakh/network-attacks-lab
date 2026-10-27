#!/usr/bin/env python3
"""
MongoDB Scanner — scans a network for MongoDB instances without password.
Usage: python3 scan.py <network> [--port PORT] [--timeout TIMEOUT]
Example: python3 scan.py 192.168.1.0/24
         python3 scan.py 192.168.1.1
"""

import socket
import struct
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORT = 27017
DEFAULT_TIMEOUT = 1.0
MAX_WORKERS = 100

# MongoDB OP_QUERY packet to list databases (no auth required)
def build_mongo_packet():
    # isMaster command as OP_QUERY
    msg = (
        b'\x41\x00\x00\x00'  # messageLength (will be set)
        b'\x01\x00\x00\x00'  # requestID
        b'\x00\x00\x00\x00'  # responseTo
        b'\xd4\x07\x00\x00'  # opCode = OP_QUERY (2004)
        b'\x00\x00\x00\x00'  # flags
        b'admin.$cmd\x00'    # fullCollectionName
        b'\x00\x00\x00\x00'  # numberToSkip
        b'\x01\x00\x00\x00'  # numberToReturn
        # BSON document: {isMaster: 1}
        b'\x13\x00\x00\x00'
        b'\x10'
        b'isMaster\x00'
        b'\x01\x00\x00\x00'
        b'\x00'
    )
    # Fix message length
    length = len(msg).to_bytes(4, 'little')
    return length + msg[4:]


def check_mongodb(ip, port, timeout):
    """
    Try to connect to MongoDB and check if it's accessible without auth.
    Returns (ip, port, info) if open, None otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        if result != 0:
            sock.close()
            return None

        # Send isMaster query
        packet = build_mongo_packet()
        sock.sendall(packet)

        # Receive response
        data = sock.recv(4096)
        sock.close()

        if len(data) > 16:
            return (str(ip), port, "MongoDB accessible (no auth)")
        return None

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


def scan_network(target, port, timeout):
    """
    Scan a single IP or CIDR network for open MongoDB instances.
    """
    results = []

    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
    except ValueError:
        # Single IP
        try:
            hosts = [ipaddress.ip_address(target)]
        except ValueError:
            print(f"[ERROR] Invalid target: {target}")
            return results

    print(f"[*] Scanning {len(hosts)} host(s) on port {port}...")
    print(f"[*] Timeout: {timeout}s | Threads: {MAX_WORKERS}\n")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_mongodb, str(host), port, timeout): host for host in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                ip, p, info = result
                print(f"[+] FOUND: {ip}:{p} — {info}")
                results.append(result)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Scan network for MongoDB instances without password."
    )
    parser.add_argument(
        "target",
        help="Target IP or CIDR network (e.g. 192.168.1.1 or 192.168.1.0/24)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=DEFAULT_PORT,
        help=f"MongoDB port (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    args = parser.parse_args()

    print("=" * 50)
    print("   MongoDB Open Instance Scanner")
    print("=" * 50)

    results = scan_network(args.target, args.port, args.timeout)

    print("\n" + "=" * 50)
    if results:
        print(f"[!] Found {len(results)} open MongoDB instance(s):")
        for ip, port, info in results:
            print(f"    {ip}:{port}")
    else:
        print("[*] No open MongoDB instances found.")
    print("=" * 50)


if __name__ == "__main__":
    main()
