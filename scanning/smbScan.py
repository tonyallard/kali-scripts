#! /usr/bin/python

#Node Scan
#Author: Tony Allard
#Description: Automatically does some basic smb scans on a target node. 

import sys
import os
import argparse

import datetime
from timeit import default_timer as timer

import scanCommon as common

SMB_FILE = "smb.txt"

def initArgs():
	parser = argparse.ArgumentParser(description='Scan a host, get some deets, swipe right...')	
	parser.add_argument('ip', type=str, help='the IP Address to scan')
	parser.add_argument("-o", help="Directory to output results")
	args = parser.parse_args()
	return args
	
def doSMBscans(ip, outputDir):
	"""NSE Scan a host with SMB
	nmap options:
		--script:	Run nmap scripts
	"""
	smbFile = "%s-%s"%(ip, SMB_FILE)
	
	f = open(os.path.join(outputDir, smbFile), 'w')
	now = datetime.datetime.now()
	f.write("%s\n"%str(now))
	#Nmap
	f.write("===NMAP NSE===\n")
	start = timer()
	out, err = common.runCommand(["nmap", "-v", "-sV", "-p %s"%",".join(common.SMB_PORTS), "--script", "*smb*.nse", ip])
	end = timer()
	f.write("%s seconds to complete.\n"%(end-start))
	f.write("===STD OUT===\n")
	f.write(out)
	f.write("\n===STD ERR===\n")
	f.write(err)
	
	#nbtscan
	f.write("===NBTSCAN===")
	start = timer()
	out, err = common.runCommand(["nbtscan", "-r", ip])
	end = timer()
	f.write("%s seconds to complete.\n"%(end-start))
	f.write("===STD OUT===\n")
	f.write(out)
	f.write("\n===STD ERR===\n")
	f.write(err)
	
	#enum4linux
	f.write("===enum4linux===")
	start = timer()
	out, err = common.runCommand(["enum4linux", "-a", ip])
	end = timer()
	f.write("%s seconds to complete.\n"%(end-start))
	f.write("===STD OUT===\n")
	f.write(out)
	f.write("\n===STD ERR===\n")
	f.write(err)

	f.close()

	return out
	
def main(args):
	#Check if IP is valid
	ip_valid = common.isValidIP(args.ip)
	if not ip_valid:
		print "Error: IP is invalid"
		sys.exit(-1)
		
	outputDir = "."
	if args.o:
		outputDir = args.o

	doSMBscans(args.ip, outputDir)


#Run Main Function
if __name__ == "__main__":
	args = initArgs()
	main(args)
