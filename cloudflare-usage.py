import sys, random, socket,hashlib, json, time, threading, os
import dns.resolver
import urllib.parse

import requests
from tranco import Tranco

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
MAX_THREADS = 100

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
		return cn
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
		domain = urllib.parse.urlparse(url).netloc
		cname = get_cname(domain)
		if cname != None:
			if cname.endswith(".fastly.net"):
				return "fastly"
		r = requests.request(url=url,method=REQUEST_METHOD,timeout=REQUEST_TIMEOUT,headers=headers)
		debugmsg("Request done!",r.headers)
		if "Via" in r.headers:
			if r.headers["Via"] not in via_headers:
				via_headers.append(r.headers["Via"])
			if r.headers["Via"].endswith(".cloudfront.net (CloudFront)"):
				return "cloudfront"
		if "Server" in r.headers:
			server_header = r.headers["Server"]
			if server_header not in server_headers and server_header != None and server_header != "":
				server_headers.append(server_header)
			if server_header == None or server_header == "":
				pass
			elif server_header.lower() == "cloudflare" or server_header == "cloudflare-nginx":
				return "cloudflare"
			elif server_header == "AkamaiGHost" or server_header == "AkamaiNetStorage":
				return "akamai"
			elif server_header == "ddos-guard":
				return "ddosguard"
			elif server_header.startswith("BunnyCDN"):
				return "bunnycdn"
			elif server_header == "myracloud":
				return "myracloud"
			elif server_header == "CDN77" or server_header.startswith("CDN77-"):
				return "cdn77"
			elif server_header.startswith("keycdn-"):
				return "keycdn"
		if "CF-RAY" in r.headers:
			return "cloudflare"
		if "x-77-age" in r.headers or "x-77-cache" in r.headers or "x-77-nzt" in r.headers or "x-77-nzt-ray" in r.headers or "x-77-pop" in r.headers:
			return "cdn77"
		if "x-cf-reqid" in r.headers:
			return "cachefly"
		if "lswcdn_country_code" in r.headers:
			return "leaseweb"
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
report_base = {
	"cdns": {
		"akamai": {
			"domains": [],
			"ips": []
		},
		"bunnycdn": {
			"domains": [],
			"ips": []
		},
		"cachefly": {
			"domains": [],
			"ips": []
		},
		"cdn77": {
			"domains": [],
			"ips": []
		},
		"cloudflare": {
			"domains": [],
			"ips": []
		},
		"cloudfront": {
			"domains": [],
			"ips": []
		},
		"ddosguard": {
			"domains": [],
			"ips": []
		},
		"fastly": {
			"domains": [],
			"ips": []
		},
		"sucuri": {
			"domains": [],
			"ips": []
		},
		"myracloud": {
			"domains": [],
			"ips": []
		},
		"keycdn": {
			"domains": [],
			"ips": []
		},
		"leaseweb": {
			"domains": [],
			"ips": []
		}
	},
	"has_nothing": 0,
	"tested": 0,
	"total": 0,
	"erroredout": 0
}
full_report = {
}
via_headers = []
server_headers = []
cnames = []

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
	print(full_report)
	for cata in full_report:
		try:
			os.mkdir(cata)
		except Exception as err:
			print(err)
		report = full_report[cata]
		for cdn in report["cdns"]:
			try:
				domainsfile = open(f"{cata}/{cdn}_domains.txt",'w',encoding="UTF-8")
				domainsfile.write("\n".join(report["cdns"][cdn]["domains"]))
				domainsfile.close()
			except Exception as err:
				debugmsg('err domains file',err)
			try:
				ipsfile = open(f"{cata}/{cdn}_ips.txt",'w',encoding="UTF-8")
				ipsfile.write("\n".join(report["cdns"][cdn]["ips"]))
				ipsfile.close()
			except Exception as err:
				debugmsg('err ips file',err)
	
		
		dtested = report["tested"]
		has_nothing = report["has_nothing"]
		erroredout = report["erroredout"]
		try:
			tested_precent = (has_nothing/dtested)*100
		except:
			tested_precent = 0
		report_contents = f"""{dtested} domains tested. {tested_precent}% were behind nothing ({(dtested - has_nothing)} were behind something). {erroredout} domains could not be tested.<br>"""
		debugmsg(report)
		for cdn in report["cdns"]:
			alldomains = "\n".join(report["cdns"][cdn]["domains"])
			report_contents += f"""
{len(report["cdns"][cdn]["domains"])} used {cdn} ({(len(report["cdns"][cdn]["domains"])/dtested)*100}%):
```
{alldomains}
```
"""
	reportfile = open(os.path.join(cata, "report.md"),'w')
	reportfile.write(report_contents)
	reportfile.close()

def checkdomain(d, cata):
	global running
	global done
	global full_report
	
	running += 1
	ips = get_ip(d)
	full_report[cata]["tested"] += 1
	if ips == None:
		running -= 1
		done += 1
		full_report[cata]["erroredout"] += 1
		return
	httptestresult = hascloudflare(f"http://{d}")
	if httptestresult == False:
		full_report[cata]["has_nothing"] += 1
	elif httptestresult != False and httptestresult != None:
		if httptestresult not in full_report[cata]["cdns"]:
			full_report[cata]["cdns"][httptestresult] = {
			"domains": [],
			"ips": []
			}
		full_report[cata]["cdns"][httptestresult]["domains"].append(d)
		full_report[cata]["cdns"][httptestresult]["ips"] += get_ip(d)
		full_report[cata]["cdns"][httptestresult]["ips"] = list(set(full_report[cata]["cdns"][httptestresult]["ips"]))
	elif httptestresult == None and RETRY_ENABLED == True:
		httpstestresult = hascloudflare(f"https://{d}")
		if httpstestresult == False:
			full_report[cata]["has_nothing"] += 1
		elif httpstestresult != False and httpstestresult != None:
			if httpstestresult not in full_report[cata]["cdns"]:
				full_report[cata]["cdns"][httpstestresult] = {
					"domains": [],
					"ips": []
				}
			full_report[cata]["cdns"][httpstestresult]["domains"].append(d)
			full_report[cata]["cdns"][httpstestresult]["ips"] = get_ip(d)
		elif httpstestresult == None:
			full_report[cata]["erroredout"] += 1
	done += 1
	running -= 1
	debugmsg(f"Done: {done} Running: {running}")


def check_domains(domains, cata):
	global running
	global full_report
	global started
	
	running = 0
	done = 0
	started = 0
	
	full_report[cata] = dict(report_base)
	full_report[cata]["total"] = len(domains)
	
	for domain in domains:
		if domain == "" or domain.startswith("#"):
			continue
		if running > MAX_THREADS:
			print("too many, sleeping", running)
			time.sleep(5)
			print("woke up", running)
		started += 1
		threading.Thread(target=checkdomain, args=(domain, cata, )).start()

	try:
		while running > 0:
			pass
	except KeyboardInterrupt:
		pass
	print("Done checking domains for cata",cata)

check_domains(topdomains, "top1000")

try:
	kdl = requests.get("https://raw.githubusercontent.com/iam-py-test/tracker_analytics/main/kdl.txt").text.split("\n")
	check_domains(kdl, "kdl")
except Exception as err:
	print(err)

try:
	urlhaus = requests.get("https://urlhaus.abuse.ch/downloads/hostfile/").text.replace("127.0.0.1\t","").replace("\r", "").split("\n")
	check_domains(urlhaus, "urlhaus")
except Exception as err:
	print(err)

savereport()
savecnames()
saveserverheaders()
saveviaheaders()
