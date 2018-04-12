#! /usr/bin/python

#SNMP Scan
#Author: Tony Allard
#Description: Automatically does some basic snmp scans on a target node. 

import sys
import os
import argparse

import re
import datetime
from timeit import default_timer as timer

import scanCommon as common

ONE_SIXTY_ONE_LOC = "/root/onesixtyone/onesixtyone"

FILE_SUFFIX = "snmp.txt"
OS_FILE = "os.txt"

def initArgs():
	parser = argparse.ArgumentParser(description='Scan a host, get some deets, swipe right...')	
	parser.add_argument('ip', type=str, help='the IP Address to scan')
	parser.add_argument("-o", help="Directory to output results")
	args = parser.parse_args()
	return args
	
def nmap_nse_scan(ip, fileHandle):
	#Nmap
	fileHandle.write("===NMAP NSE===\n")
	start = timer()
	out, err = common.runCommand(["nmap", "-v", "-sV", "-p %s"%common.SNMP_PORT, "--script", "*snmp*.nse", ip])
	end = timer()
	fileHandle.write("%s seconds to complete.\n"%(end-start))
	fileHandle.write("===STD OUT===\n")
	fileHandle.write(out)
	fileHandle.write("\n===STD ERR===\n")
	fileHandle.write(err)
	
def onesixtyone_scan(ip, fileHandle):
	tmp = open("/tmp/target.txt", 'w')
	tmp.write("%s\n"%ip);
	tmp.close();
	
	#onesixtyone
	fileHandle.write("===onesixtyone===\n")
	start = timer()
	out, err = common.runCommand([ONE_SIXTY_ONE_LOC, "-c", "/root/SecLists/Discovery/SNMP/common-snmp-community-strings.txt", "-i", "/tmp/target.txt"])
	end = timer()
	fileHandle.write("%s seconds to complete.\n"%(end-start))
	fileHandle.write("===STD OUT===\n")
	fileHandle.write(out)
	fileHandle.write("\n===STD ERR===\n")
	fileHandle.write(err)
	PW_REG = "\[.*\]"
	for pw in re.findall(PW_REG, out):
		return pw
		
def hydra_scan(ip, fileHandle):
	#Nmap
	fileHandle.write("===HYDRA===\n")
	start = timer()
	out, err = common.runCommand(["hydra", "-P", "/root/SecLists/Discovery/SNMP/common-snmp-community-strings.txt", "-v", ip, "-f", "snmp"])
	end = timer()
	fileHandle.write("%s seconds to complete.\n"%(end-start))
	fileHandle.write("===STD OUT===\n")
	fileHandle.write(out)
	fileHandle.write("\n===STD ERR===\n")
	fileHandle.write(err)
	
	PW_REG = "password: [\S]*" 
	res = re.findall(PW_REG, out)
	if res:
		for pw in res:
			return pw.split(" ")[1]
			
def extract_details(ip, fileHandle, password):
	fileHandle.write("===SNMPWALK===\n")
	start = timer()
	#enumerate windows users
	out, err = common.runCommand(["snmpwalk", "-c", password, "-v1", ip, "1.3.6.1.4.1.77.1.2.25"])
	out2 = "Windows Users\n"
	out2 += out
	err2 = err
	
	#enumerate running windows processes
	out, err = common.runCommand(["snmpwalk", "-c", password, "-v1", ip, "1.3.6.1.2.1.25.4.2.1.2"])
	out2 += "Running Windows Processes\n"
	out2 += out
	err2 += err
	
	#enumerate open tcp ports
	out, err = common.runCommand(["snmpwalk", "-c", password, "-v1", ip, "1.3.6.1.2.1.6.13.1.3"])
	out2 += "Open TCP Ports\n"
	out2 += out
	err2 += err
	
	#enumerate installed software
	out, err = common.runCommand(["snmpwalk", "-c", password, "-v1", ip, "1.3.6.1.2.1.25.6.3.1.2"])
	out2 += "Installed Software\n"
	out2 += out
	err2 += err
	
	end = timer()
	fileHandle.write("%s seconds to complete.\n"%(end-start))
	fileHandle.write("===STD OUT===\n")
	fileHandle.write(out2)
	fileHandle.write("\n===STD ERR===\n")
	fileHandle.write(err2)
	
def doScan(ip, outputDir):
	#Check if IP is valid
	ip_valid = common.isValidIP(args.ip)
	if not ip_valid:
		print "Error: IP is invalid"
		sys.exit(-1)
		
	outputDir = "."
	if args.o:
		outputDir = args.o

	outFile = "%s-%s"%(args.ip, FILE_SUFFIX)
	
	f = open(os.path.join(outputDir, outFile), 'w')
	now = datetime.datetime.now()
	f.write("%s\n"%str(now))
	password = hydra_scan(args.ip, f)
	
	if len(password):
		extract_details(args.ip, f, password)
	else:
		print "Failed to find SNMP Community String."
	
def main(args):
	#Check if IP is valid
	ip_valid = common.isValidIP(args.ip)
	if not ip_valid:
		print "Error: IP is invalid"
		sys.exit(-1)
		
	outputDir = "."
	if args.o:
		outputDir = args.o

	outFile = "%s-%s"%(args.ip, FILE_SUFFIX)
	
	f = open(os.path.join(outputDir, outFile), 'w')
	now = datetime.datetime.now()
	f.write("%s\n"%str(now))
	password = hydra_scan(args.ip, f)
	
	if len(password):
		extract_details(args.ip, f, password)
	else:
		print "Failed to find SNMP Community String."


#Run Main Function
if __name__ == "__main__":
	args = initArgs()
	main(args)
