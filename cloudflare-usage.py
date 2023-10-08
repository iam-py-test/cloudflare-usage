import sys,random,socket,hashlib, json, time, threading
import dns.resolver

import requests
from tranco import Tranco
from tqdm import tqdm

NUM_DOMAINS = 1000
UA_CHOICES = ["Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0","Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0","Microsoft Edge Legacy User-Agent string: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70..3538.102 Safari/537.36 Edge/18.19582","Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0", 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188', "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0"]
REQUEST_TIMEOUT = 50
RETRY_ENABLED = True
REPORT_FILE = "report.md"
DOMAINS_FILE = "domains.txt"
IPS_FILE = "ips.txt"
TOPHASH_FILE = "topdomains_hash.txt"
SORT_DOMAINS = True
CACHE_LIST = False # pointless with GitHub actions
REQUEST_METHOD = "HEAD" # HEAD gives us what we need
PROGRESS_BAR_ENABLED = "--noprogress" not in sys.argv # read from sys.argv, overwrite to always enable/disable
DEBUG = False # set to True when testing
MAX_THREADS = 95

def debugmsg(msg,data="No data!"):
	if DEBUG:
		print("[DEBUG] {}".format(msg),data)

trancolist = Tranco(cache=CACHE_LIST)
latest_list = trancolist.list()
topdomains = latest_list.top(NUM_DOMAINS)
debugmsg(f"Got {len(topdomains)} domains (out of {NUM_DOMAINS})")
useragent = random.choice(UA_CHOICES)
headers = {"user-agent":useragent}
running = 0
done = 0
started = 0
cnames = []
resolver = dns.resolver.Resolver()
resolver.nameservers = ["94.140.14.140", "8.8.8.8","1.1.1.1"]

erroredout = 0
seenips = {}
server_headers = []
via_headers = []
def saveip(ips, provider="cloudflare"):
	global seenips
	try:
		if provider not in seenips:
			seenips[provider] = []
		for ip in ips:
			if ip not in seenips:
				seenips[provider].append(ip)
	except:
		pass
def get_cname(domain):
	global cnames
	try:
		resp = resolver.resolve(domain)
		cn = resp.canonical_name.to_text()
		if cn.endswith("."):
			cn = cn[:-1]
		if cn == domain:
			return None
		if cn in cnames:
			return None
		cnames.append(cn)
	except:
		return None

def get_ip(domain):
	ips = []
	try:
		resp = resolver.resolve(domain)
		res = list(resp)
		for ip in res:
			ips.append(ip.address)
	except Exception as err:
		print(err)
	return ips

def hascloudflare(url):
	global server_headers
	global via_headers
	try:
		r = requests.request(url=url,method=REQUEST_METHOD,timeout=REQUEST_TIMEOUT,headers=headers)
		debugmsg("Request done!",r.headers)
		if "Via" in r.headers:
			if r.headers["Via"] not in via_headers:
				via_headers.append(r.headers["Via"])
			if r.headers["Via"].endswith(".cloudfront.net (CloudFront)"):
				return "cloudfront"
		if "Server" in r.headers:
			if r.headers["Server"] not in server_headers:
				server_headers.append(r.headers["Server"])
			if r.headers["Server"].lower() == "cloudflare" or r.headers["Server"] == "cloudflare-nginx":
				return True
			elif r.headers["Server"] == "AkamaiGHost" or r.headers["Server"] == "AkamaiNetStorage":
				return "akamai"
			elif r.headers["Server"] == "ddos-guard":
				return "ddosguard"
		if "CF-RAY" in r.headers:
			return True
		if "X-Sucuri-ID" in r.headers or "X-Sucuri-Cache" in r.headers:
			return "sucuri"
		if "X-Cache" in r.headers:
			if r.headers["X-Cache"] == "Hit from cloudfront":
				return "cloudfront"
		if "Akamai-Expedia-Global-GRN" in r.headers:
			return "akamai"
	except Exception as err:
		print("Got error while making request: ",err)
		return None
	return False

hascloud = []
hascloudfront = []
hassucuri = []
hasakamai = []
hasddosguard = []

def savedomains():
	domainsfile = open(DOMAINS_FILE,'w',encoding="UTF-8")
	domainsfile.write("\n".join(hascloud))
	domainsfile.close()
	domainsfile = open("sucuri_domains.txt",'w',encoding="UTF-8")
	domainsfile.write("\n".join(hassucuri))
	domainsfile.close()
	domainsfile = open("cloudfront_domains.txt",'w',encoding="UTF-8")
	domainsfile.write("\n".join(hascloudfront))
	domainsfile.close()
	domainsfile = open("akamai_domains.txt",'w',encoding="UTF-8")
	domainsfile.write("\n".join(hasakamai))
	domainsfile.close()
	domainsfile = open("ddosguard_domains.txt",'w',encoding="UTF-8")
	domainsfile.write("\n".join(hasddosguard))
	domainsfile.close()
def saveips():
	for p in seenips:
		ipsfile = open(f"{p}_ips.txt",'w',encoding="UTF-8")
		ipsfile.write("\n".join(seenips[p]))
		ipsfile.close()
def savecnames():
	ipsfile = open("cnames.txt",'w',encoding="UTF-8")
	ipsfile.write("\n".join(cnames))
	ipsfile.close()
def saveserverheaders():
	serverfile = open("servers.txt", 'w', encoding="UTF-8")
	serverfile.write("\n".join(server_headers))
	serverfile.close()
def saveviaheaders():
	viafile = open("via.txt", 'w', encoding="UTF-8")
	viafile.write("\n".join(via_headers))
	viafile.close()
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

def checkdomain(d):
	global erroredout
	global hascloud
	global hascloudfront
	global hassucuri
	global hasakamai
	global hasddosguard
	global running
	global done
	running += 1
	ips = get_ip(d)
	get_cname(d)
	if ips == None:
		running -= 1
		done += 1
		return
	httptestresult = hascloudflare(f"http://{d}")
	if httptestresult == True:
		hascloud.append(d)
		saveip(ips)
	elif httptestresult == "sucuri":
		hassucuri.append(d)
		saveip(ips, "sucuri")
	elif httptestresult == "cloudfront":
		hascloudfront.append(d)
		saveip(ips, "cloudfront")
	elif httptestresult == "akamai":
		hasakamai.append(d)
		saveip(ips, "akamai")
	elif httptestresult == "ddosguard":
		hasddosguard.append(d)
		saveip(ips, "ddosguard")
	elif httptestresult == None and RETRY_ENABLED == True:
		httpstestresult = hascloudflare(f"https://{d}")
		if httpstestresult == True:
			hascloud.append(d)
			saveip(ips)
		elif httpstestresult == None:
			erroredout += 1
	done += 1
	running -= 1

for d in domainsarray:
	if running > MAX_THREADS:
		print("too many, sleeping", running)
		time.sleep(5)
		print("woke up", running)
	started += 1
	threading.Thread(target=checkdomain, args=(d, )).start()

while done < started:
	pass

if SORT_DOMAINS:
	hascloud.sort()

savedomains()
saveips()
savereport()
savecnames()
saveserverheaders()
saveviaheaders()
