#! /usr/bin/python

#Node Scan
#Author: Tony Allard
#Description: Automatically does some basic scans on a target node. 

import sys
import os
import argparse

import socket
import re
import datetime
from timeit import default_timer as timer

import scanCommon as common
import portScan
import sshScan
import smbScan
import smtpScan
import snmpScan

PING_FILE = "ping.txt"

def initArgs():
	parser = argparse.ArgumentParser(description='Scan a host, get some deets, swipe right...')	
	parser.add_argument('ip', type=str, help='the IP Address to scan')
	parser.add_argument("--dns", help="DNS Server to lookup")
	parser.add_argument("-o", help="Directory to output results")
	args = parser.parse_args()
	return args

def runCommand(cmd):
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
	 	stderr=subprocess.PIPE)
	out, err = p.communicate()
	return out, err

def isValidIP(ip):
	try:
		socket.inet_aton(ip)
	except socket.error:
		return False
	return True

def ping(ip, outputDir):
	"""Ping a host
	Ping Options:
		-c 5:	Send 5 packets
		-n:	Do not resolve symbolic names (i.e. no dns lookups)
	
	Pings a host 5 times, saves results to file, and then returns
	if ping was successful	
	"""

	pingFile = "%s-%s"%(args.ip, PING_FILE)
	f = open(os.path.join(outputDir, pingFile), 'w')
	now = datetime.datetime.now()
	f.write("%s\n"%str(now))
	
	start = timer()
	out, err = common.runCommand(["ping", "-c", "5", "-n", ip])
	end = timer()
	
	f.write("%s seconds to complete.\n"%(end-start))
	
	f.write("===STD OUT===\n")
	f.write(out)
	f.write("\n===STD ERR===\n")
	f.write(err)
	f.close()

	res = re.search("[0-5]{1} received", out)
	if res:
		received = int(re.search("[0-5]{1}", res.group(0)).group(0))
		if received > 0:
			return True
	return False
	
def checkServices(ports, ip, outputDir):
	for port in ports:
		if port == common.SSH_PORT:
			sshScan.doScan(ip, outputDir)
		#if port in common.SMB_PORTS:
			#smbScan.doSMBscans(ip, outputDir)
		if port == common.SMTP_PORT:
			smtpScan.doScan(ip, outputDir)
		if port == common.SNMP_PORT:
			snmpScan.doScan(ip, outputDir)
	
def main (args):
	#Check if IP is valid
	ip_valid = isValidIP(args.ip)
	if not ip_valid:
		print "Error: IP is invalid"
		sys.exit(-1)
		
	outputDir = "."
	if args.o:
		outputDir = args.o
		
	#Ping host
	connectivity = ping(args.ip, outputDir)	
	if not connectivity:
		print "Error: Host could not be contacted"
		exit(-2)
	
	print "Host is up..."
	
	#nmap scan
	ports = portScan.doScan(args.ip, outputDir)
	print "Open Ports: %s"%ports
	
	checkServices(ports, args.ip, outputDir)
	print "Services Checked..."

#Run Main Function
if __name__ == "__main__":
	args = initArgs()
	main(args)
