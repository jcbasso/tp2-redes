#! /usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
import time
import json
import signal
import sys
import numpy
from scipy import stats
from math import sqrt, pow

TIME_EXCEEDED_TYPE = 11
MAX_HOPS = 64
NUMBER_OF_PACKAGES = 30
TIMEOUT = 5
REACHED_END_CONDITION = False

def trace(host, debug):
	print('Tracing route to host -> ' + str(host))
	ttl_to_routes = custom_traceroute(host, NUMBER_OF_PACKAGES)
	print_prediction(ttl_to_routes)
	if debug:
		print(json.dumps(ttl_to_routes, indent = 4, separators =(',', ': ')))
		with open('trace.json', 'w') as traceFile:
			json.dump(ttl_to_routes, traceFile, indent = 4, separators =(',', ': '))

# Returns {ttl -> {rtts -> {src -> [rtt]}}, mean}}
# It filters time out responses
def custom_traceroute(host, number_of_packages):
	steps = dict()
	lastValidStep = 1

	for step in range(1,MAX_HOPS+1):
		if REACHED_END_CONDITION:
			break
		src_to_rtts, mean = trace_reply_to_host(host, number_of_packages, step)
		# Don't consider timed-out responses
		if (mean < TIMEOUT):
			steps[step] = {'rtts' : src_to_rtts, 'mean' : mean}

	return steps

# Returns {src -> [rtt]}, mean
def trace_reply_to_host(host, number_of_packages, ttl):
	src_to_rtts = dict()
	mean = 0
	packetsSent = 0
	global REACHED_END_CONDITION
	
	for i in range(0, number_of_packages):
		try:
			ttlStr = '[TTL = '  + str(ttl) + '] '
			pkt = IP(dst=host, ttl=ttl) / ICMP()
			# Send the packet and get a reply
			print(ttlStr + 'about to send packet ' + str(i) +' to ' + str(host))
			start = time.time()
			reply = sr1(pkt, verbose=0, timeout=TIMEOUT)
			rtt = time.time() - start
			mean += rtt
			
			if not reply is None:
				print(ttlStr + 'sent & received answer for packet ' + str(i) + ' from source ' + str(reply.src))
				if not reply.src in src_to_rtts:
					src_to_rtts[reply.src] = [rtt]
				else:
					src_to_rtts[reply.src].append(rtt)

				packetsSent += 1

				if reply.type == TIME_EXCEEDED_TYPE:
					print(ttlStr + 'reply type is time exceeded')
				else:
					print(ttlStr + 'reply type was ' + str(reply.type))
					REACHED_END_CONDITION = True

		except KeyboardInterrupt:
			REACHED_END_CONDITION = True
			break

	mean /= packetsSent if packetsSent > 0 else 1
	return src_to_rtts, mean

# Copy pasted from Stack Overflow
def is_ip_reserved(ip):

    # https://en.wikipedia.org/wiki/Private_network

    priv_lo = re.compile("^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    priv_24 = re.compile("^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    priv_20 = re.compile("^192\.168\.\d{1,3}.\d{1,3}$")
    priv_16 = re.compile("^172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$")

    return priv_lo.match(ip) or priv_24.match(ip) or priv_20.match(ip) or priv_16.match(ip)

def print_prediction(ttl_to_routes): 
	meanSteps = calculate_mean_steps(ttl_to_routes)
	print(predict_intercontinental_steps(meanSteps))
	#print(meanSteps)

# Returns [(ips, mean)]
# Filters steps with private ips
def calculate_mean_steps(ttl_to_routes):
	meanSteps = []
	lastMean = 0
	for _, route in sorted(ttl_to_routes.items()):
		# route = {rtts -> {src -> [rtt]}}, mean}
		ips = [ip for ip in list(route['rtts']) if not is_ip_reserved(ip)]
		deltaMean = route['mean'] - lastMean
		if deltaMean < 0:
			deltaMean = 0
		lastMean = route['mean']
		if len(ips) > 0:
			# Should be only one host, it's safe to take the first one
			meanSteps.append((ips[0], deltaMean))
	return meanSteps

def predict_intercontinental_steps(mean_steps):
	outliers = []
	normals = list(mean_steps)
	# Tau technique requires samples of, at least, 3 elements
	finishedPrediction = len(normals) < 3

	while not finishedPrediction:
		n = len(normals)
		sample = numpy.array([mean for _, mean in normals])
		X = numpy.mean(sample)
		S = numpy.std(sample)
		t = stats.t.ppf(1-0.05, n)
		tau = t * (n - 1) / (sqrt(n) * sqrt((n - 2) * pow(t, 2)))
		tauS = tau * S
		print('Tau technique step with tau = ' + str(tauS) + ' | t = ' + str(t) + ' | n = ' + str(n))
		outliers.extend([(src, mean) for src, mean in normals if abs(mean - X) > tauS])
		normals = [(src, mean) for src, mean in normals if abs(mean - X) <= tauS]
		finishedPrediction = len(normals) < 3 or len(normals) == n
	return outliers

def parse_args():
	parser = argparse.ArgumentParser(description='Trace packages')
	parser.add_argument('host', help='a host to trace its route')
	parser.add_argument('--debug', dest='debug', const=True, default=False, nargs='?', help='print JSON and dump to file')
	return parser.parse_args()

args = parse_args()

trace(args.host, args.debug)
