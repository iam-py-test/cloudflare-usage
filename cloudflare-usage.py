import sys,random,socket,hashlib

import requests
from tranco import Tranco
from tqdm import tqdm

NUM_DOMAINS = 250
UA_CHOICES = ["Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0","Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0","Microsoft Edge Legacy User-Agent string: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70..3538.102 Safari/537.36 Edge/18.19582","Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"]
REQUEST_TIMEOUT = 45
RETRY_ENABLED = True
REPORT_FILE = "report.md"
DOMAINS_FILE = "domains.txt"
IPS_FILE = "ips.txt"
TOPHASH_FILE = "topdomains_hash.txt"
SORT_DOMAINS = True
CACHE_LIST = False # pointless with GitHub actions
REQUEST_METHOD = "HEAD" # HEAD gives us what we need
PROGRESS_BAR_ENABLED = "--noprogress" not in sys.argv # read from sys.argv, overwrite to always enable/disable

trancolist = Tranco(cache=CACHE_LIST)
latest_list = trancolist.list()
topdomains = latest_list.top(NUM_DOMAINS)

erroredout = 0
seenips = []

def hascloudflare(url):
	try:
		headers = {"user-agent":random.choice(UA_CHOICES)}
		r = requests.requests(url=url,method=REQUEST_METHOD,timeout=REQUEST_TIMEOUT,headers=headers)
		if "Server" in r.headers:
			return r.headers["Server"] == "cloudflare"
	except Exception:
		return None
	return False
def saveip(domain):
	global seenips
	try:
		ip = socket.gethostbyname(domain)
		if ip not in seenips:
			seenips.append(ip)
	except:
		pass
hascloud = []

def savedomains():
	domainsfile = open(DOMAINS_FILE,'w',encoding="UTF-8")
	domainsfile.write("\n".join(hascloud))
	domainsfile.close()
def saveips():
	ipsfile = open(IPS_FILE,'w',encoding="UTF-8")
	ipsfile.write("\n".join(seenips))
	ipsfile.close()
def savereport():
	reportfile = open(REPORT_FILE,'w')
	alldomains = """
""".join(hascloud)
	report = f"""{len(topdomains)} domains tested. {len(hascloud)} used CloudFlare ({(len(hascloud)/len(topdomains))*100}%). {erroredout} domains could not be tested.<br>
Domains using CloudFlare:
```
{alldomains}
```
	"""
	reportfile.write(report)
	reportfile.close()
	if TOPHASH_FILE == "" or TOPHASH_FILE == None:
		return
	tophash = open(TOPHASH_FILE,'w')
	tophash.write(hashlib.sha256(";".join(topdomains).encode()).hexdigest())
	tophash.close()

if PROGRESS_BAR_ENABLED:
	domainsarray = tqdm(topdomains)
else:
	domainsarray = topdomains

for d in domainsarray:
	httptestresult = hascloudflare(f"http://{d}")
	if httptestresult == True:
		hascloud.append(d)
		saveip(d)
	elif httptestresult == None and RETRY_ENABLED == True:
		httpstestresult = hascloudflare(f"https://{d}")
		if httpstestresult == True:
			hascloud.append(d)
			saveip(d)
		elif httpstestresult == None:
			erroredout += 1

if SORT_DOMAINS:
	hascloud.sort()

savedomains()
saveips()
savereport()
