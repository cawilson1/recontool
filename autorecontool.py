import sys
import subprocess
import shodan
import requests

def main():
	global activityList 
	activityList = []
	input = sys.argv

	#verify that there is an argument
	if(len(input) < 2):
		print("No argument given")
		exit()

	#The first argument to this module is the program to run
	command = checkCommandToRun(input[1])
	if command == "whois":
		whois(input)
	elif command == "metagoofil":
		metagoofil(input)
	elif command == "shodan":
		shodan(input)
	elif command == "all":
		runAll(input)
	#value of 0 provided in checkCommandToRun function
	elif command == 0:
		print(input[1] + " is not valid input")
		

def checkCommandToRun(arg):
	if arg == "whois":
		return "whois"
	elif arg == "metagoofil":
		return "metagoofil"
	elif arg == "shodan":
		return "shodan"
	elif arg == "all":
		return "all"
	#not a valid program to run
	else:
		return 0
	
def whois(input):
	
	size = len(input)
	#normal whois search. no option to write to file
	if size == 3:
		print("whois " + str(input[2]))
		#subprocess and all sys calls found info from python official documentation
		subprocess.call(["whois", input[2]])
		activityList.append("Performed a whois search on " + str(input[2]))
	#grep but don't write to file
	elif size == 4:
		whoisGrep(input, False)
	#grep and do write to file
	elif size == 5:
		whoisGrep(input, True)
	else:
		print("incorrect arg count")
		exit()
	print("----------------------whois search finished------------------------")

def whoisGrep(input, writeToFile):
	print(str("whois" + " " + input[2] + " | grep " + str(input[3])))
	whoisGrep = subprocess.Popen(("whois", input[2]), stdout=subprocess.PIPE)
	stringToGrep = 'grep ' + str(input[3])
	grep = subprocess.Popen(stringToGrep.split(), stdin=whoisGrep.stdout, stdout=subprocess.PIPE)
	output = grep.communicate()[0].splitlines()
	printwhois(output)
	if(writeToFile):
		writewhois(output, input[4])
		activityList.append("whois " + input[2] + " | grep " + str(input[3]) + " written to " + input[4])
	else:
		activityList.append("whois " + input[2] + " | grep " + str(input[3]))
	

def printwhois(output):
	for i in output:
		print(str(i) + "")

#write to file
def writewhois(output, fileName):
	f = open(fileName, "a")	
	for i in output:
		f.write(str(i) + "\n")

#metagoofil info from https://tools.kali.org/information-gathering/metagoofil
def metagoofil(input):
	#no file type is specified. search all possible types of files
	if len(input) == 3 or input[1] == "all":
		searchAllFileTypes(str(input[2]))
	#run org on correct args
	elif len(input) == 5:
		org = input[2]
		fileType = input[3]
		newDirectoryName = input[4]
		searchForFileType(org, fileType, newDirectoryName, False)

	else:
		print("Incorrect arg count")
		exit()
	print("----------------------metagoofil search finished------------------------")

#individual file type search
def searchForFileType(org, fileType, newDirectoryName, allFileTypes):
	htmlFileName = newDirectoryName + ".html"
	subprocess.call(["metagoofil", "-d", org, "-t", fileType, "-l", "100", "-n", "10", "-o", newDirectoryName, "-f", htmlFileName])
	#special print statement if all file types were searched	
	if(not allFileTypes):
		activityList.append("Searched " + org + " for " + fileType + " and downloaded first 10 available in directory " + newDirectoryName + " and wrote HTML Data to " + htmlFileName)

#all file type search
def searchAllFileTypes(org):
	#all types of files that can be searched with metagoofil found at edge-security.com/metagoofil.php
	allFileTypes = {"pdf", "doc", "xls", "ppt", "docx", "pptx", "xlsx"}
	#creates default directoryName
	newDirectoryName = str(org) + "filedir"
	
	#iterates through search for all fileTypes
	for fileType in allFileTypes:
		searchForFileType(org, fileType, newDirectoryName, True)
	
	activityList.append("Searched " + org + " for all file types and downloaded first 10 of each available in directory " + newDirectoryName)

#all shodan API methods found at https://developer.shodan.io/api
def shodan(input):
	
	if(input[1]== "shodan" and len(input) < 3):
		print("incorrect arg count")
		exit()	
	
	if input[2] == "hostip":
		print("\nsearching " + input[3] + "\n")
		shodanHostIP(input[3])

	elif input[2] == "dnsresolve":
		dnList = ""
		for arg in input[3:]:
			dnList += str(arg)
			if not(arg==input[len(input)-1]):
				dnList += ","
		dnsResolve(dnList)	
		print("dns search for: " + dnList)
	elif input[1] == "all":
		dnsResolve(input[2])
	else:
		print(input[2] + " is not a valid input")
		exit()
	print("----------------------shodan search finished------------------------")

def dnsResolve(dnList):
	#get/dns/resolve
	url = "https://api.shodan.io/dns/resolve?hostnames=" + dnList + "&key=" + getApiKey()
	getJSONResponse(url, False)

def shodanHostIP(IP):
	#get/shodan/host/{ip}
	url = "https://api.shodan.io/shodan/host/" + IP + "?key=" + getApiKey()
	getJSONResponse(url, True)

def getJSONResponse(url, hasDataKey):
	#line below found from https://www.youtube.com/watch?v=g4wdm488mkE
	JSONResponse = requests.get(url).json()

	#for IP search creates relevant file names to store info
	if hasDataKey:
		orgName = JSONResponse['org']
		#to store easily readable info
		fileName = str(orgName) + "Info.txt"
		#to store deeper JSON set
		dataFileName = str(orgName) + "DataValue.txt"
		
	counter = 0#for logic purposes
	for key, value in JSONResponse.iteritems():
		#IP search
		if(hasDataKey):		
			
			#for orgInfo file
			if(value != JSONResponse['data']):
				f = open(fileName, "a")
				f.write(key + " = " + str(JSONResponse[key]) + "\n")
				print(key + " = " + str(JSONResponse[key]))
				if counter == 0:
					activityList.append("Wrote info to " + fileName)
			#for deep JSON set. Does not print to console for ease of reading
			else:
				f = open(dataFileName, "a")
				f.write(str(key) + "" +  str(value) + "\n")
				if counter == 0:
					activityList.append("Wrote info to " + dataFileName)		
				
		#DNS search
		else:
			print(key + "DNS IP address is " + value)
			#append the same value to DNSIPs file
			f = open("DNSIPs.txt", "a")
			f.write(key + " = " + value + "\n")
			if counter == 0:
				activityList.append("Appended IP addresses for specified domains to DNSIPS.txt")
		counter = counter + 1

def getApiKey():
	return "ENTER YOUR SHODAN API KEY HERE TO GET THIS PROGRAM TO RUN"

def runAll(input):
	whois(input)
	metagoofil(input)
	shodan(input)


if __name__=="__main__":
	main()
	print("\n\nActivities Performed:")
	for i in activityList:
		print(str(i) + "\n")
	print("\nThis program has concluded")
	exit()
