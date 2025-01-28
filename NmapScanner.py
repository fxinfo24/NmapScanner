#!/usr/bin/python3
# NmapScanner,py
"""Automated Nmap scanning tool for network reconnaissance and security assessment."""

import nmap
import argparse
import logging
import re
import sys
import json
import csv
import ipaddress
from datetime import datetime
from tqdm import tqdm
from functools import lru_cache
import asyncio
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(
    filename="nmap_automation.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def validate_ip(ip):
    """Validate the IP address format."""
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not ip_pattern.match(ip):
        raise argparse.ArgumentTypeError(f"Invalid IP address: {ip}")
    return ip

def validate_port_range(port_range):
    """Validate the port range format."""
    try:
        start, end = map(int, port_range.split("-"))
        if start < 1 or end > 65535 or start > end:
            raise ValueError
    except ValueError:
        msg = (
            "Invalid port range: {}. "
            "Use the format 'start-end' (e.g., 20-80)."
        ).format(port_range)
        raise argparse.ArgumentTypeError(msg)
    return port_range

def validate_target(target: str) -> str:
    """Validate IP address or CIDR notation."""
    try:
        # Check if CIDR notation
        if '/' in target:
            ipaddress.ip_network(target)
        else:
            ipaddress.ip_address(target)
        return target
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid target: {target}")

@lru_cache(maxsize=128)
def cached_scan(target: str, ports: str, scan_type: str) -> Dict:
    """Cache scan results to avoid repeated scans."""
    scanner = nmap.PortScanner()
    return scanner.scan(hosts=target, ports=ports, arguments=scan_arguments[scan_type])

async def async_scan(targets: List[str], ports: str, scan_type: str) -> List[Dict]:
    """Perform async scanning of multiple targets."""
    tasks = []
    for target in targets:
        task = asyncio.create_task(
            asyncio.to_thread(cached_scan, target, ports, scan_type)
        )
        tasks.append(task)
    return await asyncio.gather(*tasks)

def save_results(results: Dict, output_file: str, format: str):
    """Save scan results in specified format."""
    if format == 'json':
        with open(f"{output_file}.json", 'w') as f:
            json.dump(results, f, indent=4)
    elif format == 'csv':
        with open(f"{output_file}.csv", 'w', newline='') as f:
            writer = csv.writer(f)
            # Add CSV writing logic here
            writer.writerow(['Host', 'Port', 'State', 'Service'])
            for host, data in results.items():
                for proto in data.all_protocols():
                    for port in data[proto].keys():
                        writer.writerow([
                            host,
                            port,
                            data[proto][port]['state'],
                            data[proto][port].get('name', 'unknown')
                        ])

def perform_scan(target, ports, scan_type, retries=3):
    """Perform an Nmap scan based on user input."""
    scan_arguments = {
        "syn": "-sS -T4 -v",
        "udp": "-sU -T4 -v", 
        "comprehensive": "-sS -sV -sC -A -O -T4 -v",
        "vulnerability": "--script=vulners -T4 -v"
    }

    for attempt in range(retries):
        try:
            # Handle CIDR notation
            targets = []
            if '/' in target:
                network = ipaddress.ip_network(target)
                targets.extend(str(ip) for ip in network.hosts())
            else:
                targets = [target]

            # Show progress bar for multiple targets
            results = {}
            with tqdm(total=len(targets), desc="Scanning") as pbar:
                if len(targets) > 1:
                    # Use async scanning for multiple targets
                    scan_results = asyncio.run(async_scan(targets, ports, scan_type))
                    for t, result in zip(targets, scan_results):
                        results[t] = result
                else:
                    # Single target scan
                    results[target] = cached_scan(target, ports, scan_type)
                pbar.update(1)

            return results

        except Exception as e:
            if attempt < retries - 1:
                logging.warning(f"Scan attempt {attempt + 1} failed: {e}. Retrying...")
                continue
            raise

def main():
    """Main function to parse arguments and execute the script."""
    parser = argparse.ArgumentParser(
        description="Enhanced Nmap Automation Script"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        type=validate_target,
        help="Target IP address or CIDR subnet to scan"
    )
    parser.add_argument(
        "-p", "--ports",
        required=True,
        type=validate_port_range,
        help="Port range to scan (e.g., 20-80)"
    )
    parser.add_argument(
        "-s", "--scan-type",
        required=True,
        choices=["syn", "udp", "comprehensive", "vulnerability"],
        help="Type of scan to perform: syn, udp, comprehensive, or vulnerability"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file name (without extension)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=['json', 'csv'],
        help="Output format (json or csv)"
    )
    parser.add_argument(
        "--timing",
        type=int,
        choices=range(0, 6),
        help="Timing template (0-5)"
    )
    args = parser.parse_args()

    try:
        results = perform_scan(args.target, args.ports, args.scan_type)
        
        # Save results if output format specified
        if args.output and args.format:
            save_results(results, args.output, args.format)
            print(f"Results saved to {args.output}.{args.format}")

    except Exception as e:
        logging.critical(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Script interrupted by user.")
        sys.exit("\nScan interrupted by user.")
    except Exception as e:
        logging.critical(f"Unexpected error: {e}")
        sys.exit(f"An unexpected error occurred: {e}")
