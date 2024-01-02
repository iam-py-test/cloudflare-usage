import numpy as np 
import matplotlib.pyplot as plt
import matplotlib.colors as allowedcolors
import json
import os

color_names = list(allowedcolors.CSS4_COLORS)
stats = json.loads(open("stats.json").read())

for pre in stats["cat_precents"]:
	try:
		os.mkdir(f"{pre}/img")
	except:
		pass
	# https://www.geeksforgeeks.org/plot-line-graph-from-numpy-array/
	for company in stats["cat_precents"][pre]:
		pre_arr = stats["cat_precents"][pre][company]
		x = np.arange(1, len(pre_arr)+1) 
		y = np.array(pre_arr)
		
		# plotting
		plt.title(f"Usage of {company}") 
		plt.xlabel("Check number") 
		plt.ylabel("Number of domains") 
		plt.plot(x, y, color ="green") 
		plt.savefig(f"{pre}/img/{company}.png")
		plt.clf()
	plt.title("Usage of all companies")
	plt.xlabel("Check number")
	plt.ylabel("Number of domains")
	cnum = 0
	for company in stats["cat_precents"][pre]:
		pre_arr = stats["cat_precents"][pre][company]
		x = np.arange(1, len(pre_arr)+1) 
		y = np.array(pre_arr)
		cnum += 1
		plt.plot(x, y, color=color_names[cnum])
		
		if cnum > len(stats["cat_precents"][pre]):
			cnum = 0
	plt.savefig(f"{pre}/img/all.png")
	plt.clf()
