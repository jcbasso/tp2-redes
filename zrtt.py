import json
import matplotlib.pyplot as plt
import numpy as np
import math

class MyClass:
    def __init__(self, ip, ttl, mean, variance):
        self.ip = ip
        self.ttl = ttl
        self.mean = mean
        self.variance = variance
    def __repr__(self):
        return repr((self.ip, self.ttl, self.mean, self.variance))

promedioRTTs = 0
total = 0
def calculateVarianceAndMean(jsonFile='trace.json'):
	global promedioRTTs
	global total
	with open(jsonFile) as data_file:
	    data = json.load(data_file)

	print
	print "-----------------------------"
	res = []

	for ttl in data:
		ip = data[ttl]["rtts"].keys()[0]
		mean = data[ttl]["mean"]*1000
		# print "Ttl: %s" % (ttl)
		# print "Ip: %s" % (ip)
		suma = 0
		n = 0
		for rtt in data[ttl]["rtts"][ip]:
			n += 1
			suma += (rtt + mean)**2
		variance = suma/(n-1)
		# print "Variance: " + str(variance)
		# print "Mean: %s" % (mean)
		# print "-----------------------------"
		dictonary = dict()
		dictonary["ip"] = str(ip)
		dictonary["ttl"] = int(ttl)
		dictonary["variance"] = variance
		dictonary["mean"] = mean
		res.append(dictonary)
	res = sorted(res,key=lambda dato: dato["ttl"])

	prevmean = 0
	for i in res:
		rtti = i["mean"] - prevmean
		if (rtti < 0 ): rtti=0
		prevmean = i["mean"]
		promedioRTTs += rtti
		i["rtti"] = rtti
		total += 1
		print rtti

	promedioRTTs = promedioRTTs / total
	print promedioRTTs
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
	plotY = []
	for dato in datos:
		x.append(i)
		i += 1
		labels.append(dato["ttl"])
		plotY.append(promedioRTTs)
		if first:
			prev = dato["mean"]
			barY.append(0)
			first = False
			continue
		barValue = dato["mean"] - prev
		if(barValue<0): barValue=0
		prev = dato["mean"]
		barY.append(dato["rtti"])

	ax.plot(x,plotY,label="Media RTTi")
	# ax.plot(x,plotY, linewidth=1,marker="o")
	ax.bar(x,barY,color="lightgreen",label='Diferencia entre RTT')
	# ax.plot(x,plotY, linewidth=1,marker="o")
	for axis in [ax.xaxis]:
		axis.set(ticks=np.arange(0.5, len(labels)), ticklabels=labels)
	plt.xlabel('Salto')
	plt.ylabel('Tiempo (ms)')
	plt.legend()
	ax.grid()
	plt.show()

def plot2(datos):
	global promedioRTTs
	fig = plt.figure()
	ax = fig.gca()
	labels = []
	barY = []
	x = []
	i = 0
	cant = 0
	suma = 0
	for dato in datos:
		suma += (dato["rtti"]-promedioRTTs)**2
		cant += 1
	suma = suma/(cant-1)

	for dato in datos:
		x.append(i)
		i += 1
		labels.append(dato["ttl"])
		barY.append((math.fabs(dato["rtti"]-promedioRTTs))/suma)

	ax.bar(x,barY,color="lightgreen")
	plt.xticks(range(len(labels)),labels)
	plt.xlabel('Salto')
	plt.ylabel('')
	plt.legend()
	plt.show()


res = calculateVarianceAndMean("trace_delhi.json")
plot1(res)
plot2(res)
