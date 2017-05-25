#! /usr/bin/env python
from scapy.all import *
import argparse
import time

timeExceededType = 11
number_of_packages = 30

def trace(host):
	ttl_to_routes = customTraceroute(host, number_of_packages)

	for ttl in ttl_to_routes:
		# sacar los promedios descartando outliers y requests que nunca volvieron

	# imprimir los promedios

def customTraceroute(host,tries):
	ttl_to_routes = dict()
    ttl = 1
    finishedTrace = False

	while not finishedTrace :
     	src_to_rtts = traceReplyTohost(host, tries, ttl)
		ttl_to_routes[ttl] = src_to_rtts
		# tipo = src_to_rtts[?].type ????????
		finishedTrace = not tipo == timeExceededType
		ttl += 1

    return ttl_to_routes

def traceReplyTohost(host, tries, ttl):
	src_to_rtts = dict()

	for i in tries:
		pkt = IP(dst=host, ttl=ttl) / ICMP()
	    # Send the packet and get a reply
	    start = time.time()
	    reply = sr1(pkt, verbose=0)
	    rtt = time.time() - start

		if not(reply.src in src_to_rtts):
			src_to_rtts[reply.src] = [rtt]
		else:
			src_to_rtts[reply.src].append(rtt)

    return src_to_rtts

def parseArgs():
    parser = argparse.ArgumentParser(description='Trace packages')
    parser.add_argument('host', help='a host to trace its route')
    parser.add_argument('--TC', dest='tracer', default=customTraceroute, const=traceroute, nargs='?',
            help='which traceroute implementation to use (default "traceroute")')
    return parser.parse_args()

args = parseArgs()

print args.tracer(args.host)
