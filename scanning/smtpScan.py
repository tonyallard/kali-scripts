#! /usr/bin/python

#Node Scan
#Author: Tony Allard
#Description: Automatically does some basic smb scans on a target node. 

import sys
import os
import argparse

import socket
import datetime
from timeit import default_timer as timer

import scanCommon as common

SMTP_FILE = "smtp.txt"

def initArgs():
	parser = argparse.ArgumentParser(description='Scan a host, get some deets, swipe right...')	
	parser.add_argument('ip', type=str, help='the IP Address to scan')
	parser.add_argument("-o", help="Directory to output results")
	args = parser.parse_args()
	return args
	
def user_scan(ip, fileHanle):
	#verify users
	fileHanle.write("===VRFY Users===\n")
	start = timer()
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect((ip, 25))
	out = s.recv(1024)
	userlist = open("/root/SecLists/Usernames/top-usernames-shortlist.txt", 'r')
	#Verify users
	for user in userlist:
		vrfycmd = 'VRFY ' + user + '\r\n'
		out += vrfycmd
		s.send(vrfycmd)
		out += s.recv(1024)
	s.close()
	userlist.close()
	end = timer()
	fileHanle.write("%s seconds to complete.\n"%(end-start))
	fileHanle.write(out)

def nmap_nse_scan(ip, fileHandle):
	"""NSE Scan a host with smtp
	nmap options:
		--script:	Run nmap scripts
	"""
	#nmap NSE
	fileHandle.write("===nmap NSE===\n")
	start = timer()
	out, err = common.runCommand(["nmap", "-v", "-sV", "-p %s"%common,SMTP_PORT, "--script", "*smtp*.nse", ip])
	end = timer()
	fileHandle.write("%s seconds to complete.\n"%(end-start))
	fileHandle.write("===STD OUT===\n")
	fileHandle.write(out)
	fileHandle.write("\n===STD ERR===\n")
	fileHandle.write(err)


def doScan(ip, outputDir):
	fileName = "%s-%s"%(ip, SMTP_FILE)
	
	f = open(os.path.join(outputDir, fileName), 'w')
	now = datetime.datetime.now()
	f.write("%s\n"%str(now))
	
	user_scan(ip, f)
	nmap_nse_scan(ip, f)
	
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

	doScan(args.ip, outputDir)


#Run Main Function
if __name__ == "__main__":
	args = initArgs()
	main(args)
