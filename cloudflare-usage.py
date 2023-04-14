import sys,random,socket

import requests
from tranco import Tranco
from tqdm import tqdm

NUM_DOMAINS = 20
UA_CHOICES = ["Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0","Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0","Microsoft Edge Legacy User-Agent string: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70..3538.102 Safari/537.36 Edge/18.19582"]
REQUEST_TIMEOUT = 45
RETRY_ENABLED = True
REPORT_FILE = "report.md"
DOMAINS_FILE = "domains.txt"
IPS_FILE = "ips.txt"

t = Tranco(cache=False)
latest_list = t.list()
topdomains = latest_list.top(NUM_DOMAINS)

erroredout = 0
seenips = []

def hascloudflare(url):
	try:
		headers = {"user-agent":random.choice(UA_CHOICES)}
		r = requests.head(url,timeout=REQUEST_TIMEOUT,headers=headers)
		if "Server" in r.headers:
			return r.headers["Server"] == "cloudflare"
	except Exception as err:
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

if "--noprogress" in sys.argv:
	domainsarray = topdomains
else:
	domainsarray = tqdm(topdomains)

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

savedomains()
saveips()
savereport()
