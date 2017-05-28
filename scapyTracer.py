#! /usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
import time
import json

TIME_EXCEEDED_TYPE = 11
MAX_HOPS = 64
NUMBER_OF_PACKAGES = 30
TIMEOUT = 5
REACHED_END_CONDITION = False

def trace(host):
	ttl_to_routes = custom_traceroute(host, NUMBER_OF_PACKAGES)
	print(json.dumps(ttl_to_routes, indent = 4, separators =(',', ': ')))

def custom_traceroute(host, number_of_packages):
	ttl_to_routes = dict()

	for i in range(1,MAX_HOPS+1):
		if REACHED_END_CONDITION:
			break
		src_to_rtts = trace_reply_to_host(host, number_of_packages, i)
		ttl_to_routes[i] = src_to_rtts

	return ttl_to_routes

def trace_reply_to_host(host, number_of_packages, ttl):
	src_to_rtts = dict()

	for i in range(0,number_of_packages):

		pkt = IP(dst=host, ttl=ttl) / ICMP()
		# Send the packet and get a reply
		start = time.time()
		print('about to send packet ' + str(i) +' to ' + str(host))
		reply = sr1(pkt, verbose=0, timeout= TIMEOUT)
		rtt = time.time() - start

		if not (reply is None):
			print('sent & received answer for packet ' + str(i) + ' from source ' + str(reply.src))
			if not(reply.src in src_to_rtts):
				src_to_rtts[reply.src] = [rtt]
			else:
				src_to_rtts[reply.src].append(rtt)

			if reply.type == TIME_EXCEEDED_TYPE:
				print('reply type is time exceeded')
			else:
				print('reply type was ' + str(reply.type))
				global REACHED_END_CONDITION
				REACHED_END_CONDITION = True

	return src_to_rtts

def parseArgs():
    parser = argparse.ArgumentParser(description='Trace packages')
    parser.add_argument('host', help='a host to trace its route')
    return parser.parse_args()

args = parseArgs()

trace(args.host)
