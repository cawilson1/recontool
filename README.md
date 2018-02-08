README.md

!!!Requires metagoofil: On Kali, "apt-get install metagoofil"
!!!Must have shodan api library installed: https://shodan.readthedocs.io/en/latest/tutorial.html#installation

Whois, ShodanAPI, and Metagoofil all tested on Kali Linux.

For this program to run, you must enter your API key where it says "ENTER YOUR SHODAN API KEY HERE TO GET THIS PROGRAM TO RUN"

Only tested for Python 2.7

##########################################################################################


SIMPLE COMMAND TO RUN ALL TOOLS AT ONCE (Takes the longest time to run):
python autorecontool.py all <website name>


General Command Line Entry: python autorecontool.py <Tool> <program args>



whois command line call:
There are three possible calls to be made with whois, a normal search, a pattern matching 
search, and a pattern matching search that stores the result to a file
Command Line Examples:
General: python autorecontool.py whois <website name> <pattern (optional)> <file to save (optional)>

1) python autorecontool.py whois google.com
#returns same result as normal whois search for google.com

2)python autorecontool.py whois google.com NS
#greps the result of the search with "NS". In this example it would return:
#   Name Server: NS1.GOOGLE.COM
#   Name Server: NS2.GOOGLE.COM
#   Name Server: NS3.GOOGLE.COM
#   Name Server: NS4.GOOGLE.COM
#   DNSSEC: unsigned
#DNSSEC: unsigned

3)python autorecontool.py whois google.com NS googleNameServers.txt
#same output as before but saves all lines matching specified pattern to googleNameServers.txt




Metagoofil command line calls:
Searches for a specified filetype at specified domain name with user input directory to save to. If 
no specification is made about filetype or directory name, all file types are searched for (pdf, doc,
xls, ppt, docx, pptx, xlsx) and stored in an automatically named directory.
General: python autorecontool.py metagoofil <domain name> <file type (optional)> <directory name (optional)>

1) python autorecontool.py metagoofil google.com pdf googlepdfs
#attempts to download first 10 available pdfs from google.com. Saves results in googlepdfs directory
#and creates googlepdfs.html which performs analysis on information gathered

2) python autorecontool.py metagoofil google.com
#searches all file types specified above, and stores in directory google.comfildir, and stores 
#analysis of files in html file google.comfiledir.html.

If the file type argument is used, the directory name argument must also be used.



Shodan API Calls:
There are two shodan API methods that can be called:
1) get /shodan/host/{ip}
2) get /dns/resolve

Command Line Examples:
General: python autorecontool.py shodan <methodToCall> <args>

1)python autorecontool.py shodan hostip 216.58.216.238
#returns various info, such as region code, organization name, isp, country code, latitude 
#and longitude. Only works for a single ip address as argument. Writes to <orgname>Info.txt
#and <orgname>DataInfo.txt. Prints same values as <orgname>Info.txt to conosole

2a)python autorecontool.py shodan dnsresolve google.com
2b)python autorecontool.py shodan dnsresolve google.com bing.com facebook.com nothing.com
#enter hostnames as arguments and program returns the hostname and the associated IP address for
#each hostname. Any number of hostnames greater than 0 can be entered as arguments. Writes result
#to console and DNSIPs.txt



All commands run:
Only has two options, grepping whois call or not grepping whois call
General: python autorecontool.py all <org name> <pattern to match (optional)>

1) python autorecontool.py all google.com
#performs whois option 1), searches for all relevant file types at google.com and stores in
#appropriate directories (Metagoofil option 2), and performs option 2a of shodan API call (only
#one domain name to search) and writes relevant results

2) python autorecontool.py all google.com Email
#Same as above but only returns lines with pattern matching "Email" on whois search

