# This version is designed to parse Nessus v8 log files.
# For earlier versions of Nessus use v7 of the script.

import re,sys,getopt

#Generates the list
def genList(pluginName,pluginTime,pluginAssociatedIP,list):
	list.append([pluginName,pluginTime,pluginAssociatedIP])

def main(argv):	

	getTotalRunTime = 0.0
	ifile = "nessusd.messages"
	ofile = "nessusd.result"
	list = [] #linked list
	found = 0; index = 0;
	dictionary = {};
	pattern1 = r"\[scan=[^]]*\]\[target=[^]]*\]\[plugin=[^]]*\]" #get the job uuid
	pattern3 = r"([^'='^\s]*.nasl|[^'='^\s]*.nbin)" #plugin filename
	pattern4 = r"(\d*\.\d*s|\ds)"
	pattern5 = r"target=([^]]*)"
	
	
	pattern6 = r"\[scan=[^]]*\]"
	
	try:
		with open(ifile) as inf:
			data = inf.readlines()
	except IOError: 
		print("nessusd.messages does not exist.")
		exit(-1);
		
	
	if len(sys.argv) < 2: # no arguments provided.
		print("Valid jobs\n")
		for line in data:
			if 'duration=' in line:
				match = re.search(pattern1, line)
				if match != None:
					match = re.search(pattern6, line)
					if match not in dictionary: # so add it
						dictionary[match.group()] = match; #adds item into dictionary
						index+=1;
					
					
		for i in dictionary.items():
			print("Record",i[0])
			
		print("Usage: "+sys.argv[0]+" JOB_UUID");
		sys.exit()

	for line in data:
		if line.find("duration=") != -1 and sys.argv[1] in line != -1 and len(sys.argv[1]) == 52:	  # get running time info only that matches the job_uuid.
			found = 1
			# get pluginname
			try:
				getPluginName = re.search(pattern3, line) 
				getPluginName = getPluginName[0]
				
				
				# get plugintime
				getPluginTime = re.search(pattern4, line)
				getPluginTime = getPluginTime[0].replace("s","")
				
				
				pluginAssociatedHost = re.search(pattern5, line) # get the plugin target IP/host
				pluginAssociatedHost = pluginAssociatedHost[0]
				
				genList(getPluginName,getPluginTime,pluginAssociatedHost,list)
				
				getTotalRunTime += float(getPluginTime)
				
			
			except: 
				print(line) # complete.
				#break
			
			
			
			
	if found==0:
		print("No valid UUID found in nessusd.messages")
		exit(-3)

	# sort the list in descending order
	list = sorted(list, key=lambda x: float(x[1]), reverse=True)

	# presentation
	fo = open(ofile, "w+")
	for i in list:
		seq = "Plugin: " + list[index][0] + " ran in " + list[index][1] + " seconds" + " for " + list[index][2]
		print(seq)
		fo.writelines(seq + "\n")
		index += 1
	print("\nTotal plugin runtime: ", round(getTotalRunTime,2))

if __name__ == "__main__":
   main(sys.argv[1:])








