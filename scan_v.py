import os
import sys
import subprocess
from scapy.all import ARP, Ether, srp
import nmap
import netifaces as ni
import ipaddress

# Function to discover devices on the local network using ARP scanning
def discover_devices(ip_range):
    # Create an ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    # Send the packet and capture the response
    result = srp(arp_request, timeout=3, verbose=0)[0]
    # Extract the IP and MAC addresses from the response
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# Function to perform vulnerability scanning using Nmap
def scan_vulnerabilities(ip):
    # Create an Nmap scanner object
    scanner = nmap.PortScanner()  
    # Perform the scan for all TCP ports
    scanner.scan(ip, arguments='-p 1-65535')   
    # Print the open ports and vulnerabilities
    for host in scanner.all_hosts():
        print(f"Open ports for {host}:")
        for port in scanner[host].all_tcp():
            print(f"Port {port} is open")
        print("Vulnerabilities:")
        for script in scanner[host].scripts_results:
            print(script)

def find_router_ip():
    try:
        # Get a list of available network interfaces
        interfaces = ni.interfaces()
        # Iterate over the interfaces and find the router's IP address
        for interface in interfaces:
            if interface != 'lo':
                # Get the IPv4 addresses assigned to the interface
                addresses = ni.ifaddresses(interface).get(ni.AF_INET)
                # Check if there are any addresses assigned
                if addresses:
                    for address in addresses:
                        if 'broadcast' in address:
                            # Get the IP address and convert it to an ipaddress.IPv4Address object
                            router_ip = ipaddress.IPv4Address(address['broadcast'])
                            # Check if the router's IP address falls within the specified ranges
                            if(ipaddress.ip_address('192.168.0.0') <= router_ip <= ipaddress.ip_address('192.168.255.255')):
                                return '192.168.0.0/16'
                            elif(ipaddress.ip_address('172.16.0.0') <= router_ip <= ipaddress.ip_address('172.31.255.255')):
                                return '172.16.0.0/12'
                            elif(ipaddress.ip_address('10.0.0.0') <= router_ip <= ipaddress.ip_address('10.255.255.255')):
                                return '10.0.0.0/8'
                            else:
                                return router_ip
        # If no router IP address is found
        return "Router IP address not found"
    except ValueError as e:
        return str(e)

# Main function
def main():
    # Get the local network IP range
    router_ip_range = find_router_ip()
    if '/' in router_ip_range:
        ip_range = router_ip_range
    else:
        quit
    # Discover devices on the local network
    devices = discover_devices(ip_range)
    # Print the discovered devices
    print("Devices on the network:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
    # Perform vulnerability scanning for each device
    for device in devices:
        print(f"\nScanning vulnerabilities for {device['ip']}...")
        scan_vulnerabilities(device['ip'])

if __name__ == '__main__':
    main()