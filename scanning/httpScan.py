#! /usr/bin/python

#HTTP Scan
#Author: Tony Allard
#Description: Automatically does some basic HTTP scans on a target node. 

import sys
import os
import argparse

import datetime
from timeit import default_timer as timer

import scanCommon as common

FILE_SUFFIX = "http.txt"

def initArgs():
	parser = argparse.ArgumentParser(description='Scan a host, get some deets, swipe right...')	
	parser.add_argument('ip', type=str, help='the IP Address to scan')
	parser.add_argument("-o", help="Directory to output results")
	args = parser.parse_args()
	return args
	
def nmap_nse_scan(ip, fileHandle):
	"""NSE Scan a host with HTTP
	nmap options:
		--script:	Run nmap scripts
	"""
	#Nmap
	fileHandle.write("===NMAP NSE===\n")
	start = timer()
	out, err = common.runCommand(["nmap", "-v", "-sV", "-p 80,443", "--script", "*http*.nse", ip])
	end = timer()
	fileHandle.write("%s seconds to complete.\n"%(end-start))
	fileHandle.write("===STD OUT===\n")
	fileHandle.write(out)
	fileHandle.write("\n===STD ERR===\n")
	fileHandle.write(err)

def curl_grab(ip, fileHandle):
	fileHandle.write("===CURL===\n")
	start = timer()
	out, err = common.runCommand(["curl", "-v", ip])
	end = timer()
	fileHandle.write("%s seconds to complete.\n"%(end-start))
	fileHandle.write("===STD OUT===\n")
	fileHandle.write(out)
	fileHandle.write("\n===STD ERR===\n")
	fileHandle.write(err)
	
def goBuster_scan(ip, fileHandle):
	fileHandle.write("===GoBuster===\n")
	start = timer()
	out, err = common.runCommand(["gobuster", "-e", "-u", "http://%s/"%ip, "-w", "/root/SecLists/Discovery/Web-Content/big.txt"])
	end = timer()
	fileHandle.write("%s seconds to complete.\n"%(end-start))
	fileHandle.write("===STD OUT===\n")
	fileHandle.write(out)
	fileHandle.write("\n===STD ERR===\n")
	fileHandle.write(err)
	
def dirb_scan(ip, fileHandle):
	fileHandle.write("===dirb===\n")
	start = timer()
	out, err = common.runCommand(["dirb", "http://%s/"%ip, "/root/SecLists/Discovery/Web-Content/big.txt", "-r"])
	end = timer()
	fileHandle.write("%s seconds to complete.\n"%(end-start))
	fileHandle.write("===STD OUT===\n")
	fileHandle.write(out)
	fileHandle.write("\n===STD ERR===\n")
	fileHandle.write(err)
	
def doScan(ip, outputDir):
	outFile = "%s-%s"%(args.ip, FILE_SUFFIX)
	
	f = open(os.path.join(outputDir, outFile), 'w')
	now = datetime.datetime.now()
	f.write("%s\n"%str(now))
	
	curl_grab(ip, f)
	goBuster_scan(ip, f)
	
	f.close()

def main(args):
	#Check if IP is valid
	ip_valid = common.isValidIP(args.ip)
	if not ip_valid:
		print "Error: IP is invalid"
		sys.exit(-1)
		
	outputDir = "."
	if args.o:
		outputDir = args.o

	doScan(args.ip, outputDir)


#Run Main Function
if __name__ == "__main__":
	args = initArgs()
	main(args)
