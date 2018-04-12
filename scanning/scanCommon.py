#! /usr/bin/python

#Node Scan
#Author: Tony Allard
#Description: Common functions for scanning

import sys
import os

import socket
import subprocess

SSH_PORT = "22"
SMB_PORTS = ["139", "445"]
SMTP_PORT = "25"
SNMP_PORT = "161"

def isValidIP(ip):
	try:
		socket.inet_aton(ip)
	except socket.error:
		return False
	return True
	
def runCommand(cmd):
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
	 	stderr=subprocess.PIPE)
	out, err = p.communicate()
	return out, err
