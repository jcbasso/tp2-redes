import json
import matplotlib.pyplot as plt
import numpy as np

class MyClass:
    def __init__(self, ip, ttl, mean, variance):
        self.ip = ip
        self.ttl = ttl
        self.mean = mean
        self.variance = variance
    def __repr__(self):
        return repr((self.ip, self.ttl, self.mean, self.variance))

def calculateVarianceAndMean(jsonFile='trace.json'):
	with open(jsonFile) as data_file:
	    data = json.load(data_file)

	print
	print "-----------------------------"
	res = []
	for ttl in data:
		ip = data[ttl]["rtts"].keys()[0]
		mean = data[ttl]["mean"]*1000
		print "Ttl: %s" % (ttl)
		print "Ip: %s" % (ip)
		suma = 0
		n = 0
		for rtt in data[ttl]["rtts"][ip]:
			n += 1
			suma += (rtt + mean)**2
		variance = suma/(n-1)
		print "Variance: " + str(variance)
		print "Mean: %s" % (mean)
		print "-----------------------------"
		dictonary = dict()
		dictonary["ip"] = str(ip)
		dictonary["ttl"] = int(ttl)
		dictonary["variance"] = variance
		dictonary["mean"] = mean
		res.append(dictonary)
	res = sorted(res,key=lambda dato: dato["ttl"])
	return res

def plot1(datos):
	fig = plt.figure()
	ax = fig.gca()
	labels = []
	plotY = []
	barY = []
	x = []
	i = 0
	prev = 0
	first = True
	for dato in datos:
		x.append(i)
		i += 1
		labels.append(dato["ip"])
		plotY.append(dato["variance"])
		if first:
			prev = dato["mean"]
			barY.append(0)
			first = False
			continue
		barValue = dato["mean"] - prev
		prev = dato["mean"]
		barY.append(barValue)

	# ax.plot(x,plotY, linewidth=1,marker="o")
	ax.bar(x,barY,color="lightgreen",label='RTT Normalizado')
	# ax.plot(x,plotY, linewidth=1,marker="o")
	for axis in [ax.xaxis]:
		axis.set(ticks=np.arange(0.5, len(labels)), ticklabels=labels)
	plt.xticks(rotation=60)
	plt.xlabel('Direccion Ip')
	plt.ylabel('Tiempo (ms)')
	plt.legend()
	ax.grid()
	plt.show()

def plot2(datos):
	fig = plt.figure()
	ax = fig.gca()
	labels = []
	plotY = []
	barY = []
	x = []
	i = 0
	for dato in datos:
		x.append(i)
		i += 1
		labels.append(dato["ip"])
		plotY.append(dato["variance"])
		barY.append(dato["mean"])
	ax.bar(x,barY,color="lightgreen",label='Promedio RTT')
	plt.xticks(range(len(labels)),labels,rotation=40)
	plt.xlabel('Direccion Ip')
	plt.ylabel('Tiempo (ms)')
	plt.legend()
	plt.show()


res = calculateVarianceAndMean("kenya_uni.json")
plot1(res)
plot2(res)