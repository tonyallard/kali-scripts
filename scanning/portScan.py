#! /usr/bin/python

#Node Scan
#Author: Tony Allard
#Description: Automatically does some basic port scans on a target node. 

import sys
import os
import argparse

import socket
import re
import datetime
from timeit import default_timer as timer

import scanCommon as common

ONE_TWO_PUNCH_LOC = "/root/onetwopunch/onetwopunch.sh"

PORT_SCAN_FILE = "ports.txt"
OS_FILE = "os.txt"

def initArgs():
	parser = argparse.ArgumentParser(description='Scan a host, get some deets, swipe right...')	
	parser.add_argument('ip', type=str, help='the IP Address to scan')
	parser.add_argument("-o", help="Directory to output results")
	args = parser.parse_args()
	return args
	
def extractPorts(text, tcp=True):
	NMAP_PORT_REG = "([0-9]{1,3}/[tcp|udp])"

	PORT_NO_REG = "[0-9]{1,3}"
	ports = set()
	for port in re.findall(NMAP_PORT_REG, text):
		nums = re.findall(r'\d+', port)
		for num in nums:
			ports.add(num)
			
	return ports
	
def extractOS(text, ip, outputDir):
	OS_REG = "([0-9]{1,3}/[tcp|udp].*)|(OS CPE: .*)|(OS details: .*)|(Service Info: .*)|(Running: .*)"
	fileName = "%s-%s"%(ip, OS_FILE)
	f = open(os.path.join(outputDir, fileName), 'w')
	now = datetime.datetime.now()
	f.write("%s\n"%str(now))
	
	f.write("===NMAP OUT===\n")
	for res in re.findall(OS_REG, text):
		for r in res:
			if len(r):
				f.write("'{0}'\n".format(r))

	f.close()
	
	
def nmap_scan(ip, fileHandle, tcp=True, top1024=True):
	"""Portscan a host
	nmap options:
		-v:	verbose
		-A:	Enable OS detection, version detection, script scanning, and traceroute
		-n:	Do not resolve symbolic names (i.e. no dns lookups)
	"""
	
	ports = "1-1024"
	if not top1024:
		ports = "1-65535"
	
	if tcp:
		start = timer()
		out, err = common.runCommand(["nmap", "-v", "-n", "-A", "-p", "%s"%ports, "-sV", ip])
		end = timer()
		fileHandle.write("%s seconds to complete.\n"%(end-start))
		fileHandle.write("===STD OUT===\n")
		fileHandle.write(out)
		fileHandle.write("\n===STD ERR===\n")
		fileHandle.write(err)
		return out
	else:
		start = timer()
		out, err = common.runCommand(["nmap", "-v", "-n", "-p", "%s"%ports, "-sU", ip])
		end = timer()
		fileHandle.write("%s seconds to complete.\n"%(end-start))
		fileHandle.write("===STD OUT===\n")
		fileHandle.write(out)
		fileHandle.write("\n===STD ERR===\n")
		fileHandle.write(err)
		return out

def onetwopunch_scan(ip, fileHandle, tcp=False):
	"""Portscan a host
	onetwopunch options:
		-t:		target list is saved in /tmp/target.txt
		-p:		port range is all or just tcp
		-i tap0:	Make sure you direct it out the right interface
		-A:		Enable OS detection, version detection, script scanning, and traceroute
	"""
	
	ports = "all"
	if tcp:
		ports = "tcp"
		
	tmp = open("/tmp/target.txt", 'w')
	tmp.write("%s\n"%ip);
	tmp.close();
		
	start = timer()
	out, err = common.runCommand([ONE_TWO_PUNCH_LOC, "-t", "/tmp/target.txt", "-p", "%s"%ports, "-i", "tap0", "-n", "-A"])
	end = timer()
	fileHandle.write("%s seconds to complete.\n"%(end-start))
	fileHandle.write("===STD OUT===\n")
	fileHandle.write(out)
	fileHandle.write("\n===STD ERR===\n")
	fileHandle.write(err)
	return out
	
def doScan(ip, outputDir, oneTwoPunch=True, tcp=True, top1024=True):
	
	filename = ""
	if oneTwoPunch:
		if tcp:
			fileName = "%s-%s-%s"%(ip, "tcp", PORT_SCAN_FILE)
		else:
			fileName = "%s-%s-%s"%(ip, "all", PORT_SCAN_FILE)
	else:
		if tcp:
			if top1024:
				fileName = "%s-%s-%s-%s"%(ip, "tcp", "top1024", PORT_SCAN_FILE)
			else:
				fileName = "%s-%s-%s-%s"%(ip, "tcp", "all", PORT_SCAN_FILE)
		else:
			if top1024:
				fileName = "%s-%s-%s-%s"%(ip, "udp", "top1024", PORT_SCAN_FILE)
			else:
				fileName = "%s-%s-%s-%s"%(ip, "udp", "all", PORT_SCAN_FILE)
	
	f = open(os.path.join(outputDir, fileName), 'w')
	#f_OS = open(o
	now = datetime.datetime.now()
	f.write("%s\n"%str(now))
	
	#straight nmap
	out = nmap_scan(ip, f, tcp, top1024)
	extractOS(out, ip, outputDir)
	ports = extractPorts(out)
	out = nmap_scan(ip, f, not tcp, top1024)
	ports = ports.union(extractPorts(out))
	
	#one, two, punch
	#out = onetwopunch_scan(ip, f, False)
	#extractOS(out, ip, outputDir)
	#ports = extractPorts(out)
		
	return ports
	
def main(args):
	#Check if IP is valid
	ip_valid = common.isValidIP(args.ip)
	if not ip_valid:
		print "Error: IP is invalid"
		sys.exit(-1)
		
	outputDir = "."
	if args.o:
		outputDir = args.o
		
	ports = doScan(args.ip, outputDir)

	print "Open Ports: %s"%ports


#Run Main Function
if __name__ == "__main__":
	args = initArgs()
	main(args)
