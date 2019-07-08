# Determines which plugins contribute to long running scan times.

# This version is designed to parse Nessus v8 log files ( nessusd.messages )
# For earlier versions of Nessus use v7 of the script.
# Run scriptv8.py on it's own to display the usage.
# Valid job UUIDs are displayed if arguments are blank. Valid argument is the job_uuid

# Displays results in descending order based on how long the plugin ran for.


# Example output.
# ---------------
# python scriptv8.py
# Valid jobs
#
# Record [scan=46507114-3ae6-179f-01f4-fe2a7ee9fe803dc3ce9a9da56995]
# Record [scan=61a23661-fbef-e507-8dc7-13a4636cf495c5135e439f346cba]
# Usage: scriptv8.py JOB_UUID
#
#
#
# scriptv8.py 46507114-3ae6-179f-01f4-fe2a7ee9fe803dc3ce9a9da56995
# [Fri Mar 29 11:53:35 2019][4880.0][scan=46507114-3ae6-179f-01f4-fe2a7ee9fe803dc3ce9a9da56995][target=192.168.60.128][duration=107.09s] : Finished

# [Fri Mar 29 11:57:31 2019][4880.0][scan=46507114-3ae6-179f-01f4-fe2a7ee9fe803dc3ce9a9da56995][target=172.26.84.155][duration=343.19s] : Finished

# [Fri Mar 29 11:57:32 2019][4880.0][scan=46507114-3ae6-179f-01f4-fe2a7ee9fe803dc3ce9a9da56995][duration=344.00s] : Finished: 2 of 2 hosts up, 0 unscanned, 0 rejected, 0 dead, 0 timeout, 0 aborted

# Plugin: find_service.nasl ran in 80.05 seconds for target=172.26.84.155
# Plugin: no404.nasl ran in 63.93 seconds for target=172.26.84.155
# Plugin: ssl_supported_versions.nasl ran in 57.60 seconds for target=172.26.84.155
# Plugin: os_fingerprint_html.nasl ran in 49.07 seconds for target=172.26.84.155
# Plugin: ike2_detect.nasl ran in 36.00 seconds for target=192.168.60.128
# Plugin: ssh_get_info2.nasl ran in 33.03 seconds for target=192.168.60.128
# Plugin: traceroute.nasl ran in 32.06 seconds for target=172.26.84.155
# Plugin: scada_profinet_network_detect.nbin ran in 30.00 seconds for target=172.26.84.155
# Plugin: ssh_rate_limiting.nasl ran in 22.04 seconds for target=172.26.84.155
# ....



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








