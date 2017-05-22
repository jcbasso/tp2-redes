#! /usr/bin/env python
from scapy.all import *
import argparse
import time

timeExceededType = 11

def customTraceroute(host):
    ttl = 1
    finishedTrace = False
    while not finishedTrace :
        src,tipo,rtt = traceReplyTohost(host, ttl)
        print src + ' with RTT -> ' + rtt
        ttl += 1
        finishedTrace = not tipo == timeExceededType

def traceReplyTohost(host, ttl):
    pkt = IP(dst=host, ttl=ttl) / ICMP()
    # Send the packet and get a reply
    start = time.time()
    reply = sr1(pkt, verbose=0)
    rtt = time.time() - start
    return reply.src, reply.type, str(rtt)

def parseArgs():
    parser = argparse.ArgumentParser(description='Trace packages')
    parser.add_argument('host', help='a host to trace its route')
    parser.add_argument('--TC', dest='tracer', default=traceroute, const=customTraceroute, nargs='?',
            help='which traceroute implementation to use (default "traceroute")')
    return parser.parse_args()

args = parseArgs()

args.tracer(args.host)
