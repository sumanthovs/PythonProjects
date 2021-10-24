#!/usr/bin/env python3

import argparse
import ipinfo
import ipaddress

parser = argparse.ArgumentParser()

parser.add_argument('-a','--access_token',required=True,help='Enter the access token')
parser.add_argument('-t','--target',help='Enter a single IP Address')
parser.add_argument('-f','--file',help='Give file name as a input')
parser.add_argument('-c','--cidr',help='Give a CIDR as a input to find geo location')
parser.add_argument('-o','--output',help='Writes the Output to a file')

args=parser.parse_args()

access_token = args.access_token

handler = ipinfo.getHandler(access_token)

def lookup_ip(addr):
	try:
		addr = ipaddress.ip_address(addr)
		details = handler.getDetails(addr)
		print(f"{addr} located at {details.city} and belongs to {details.org}")
	except ValueError:
		print(f"{addr} located at {details.city} is not a valid address")

def file(file_name):
	with open(file_name) as f:
		addr = f.readlines()
		for ip in addr:
			ip = ip.strip()
			if '/' in ip:
				cidr(ip)
			else:
				details = handler.getDetails(ip)
				print(f"{ip} located at {details.city} belongs to {details.org}")

def cidr(range):
	range = ipaddress.IPv4Network(range)
	for ip in range:
		details = handler.getDetails(ip)
		print(f"{ip} located at {details.city} belongs to {details.org}")

if __name__ == "__main__":
	if args.target:
		lookup_ip(args.target)
	if args.file:
		file(args.file)
	if args.cidr:
		cidr(args.cidr)
