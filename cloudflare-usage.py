import sys, random, socket,hashlib, json, time, threading, os
import dns.resolver
import urllib.parse
import copy
from datetime import datetime, timedelta

import requests
from tranco import Tranco

NUM_DOMAINS = 1000
UA_CHOICES = open("data/user_agents.txt").read().split("\n")
REQUEST_TIMEOUT = 80
RETRY_ENABLED = True
SORT_DOMAINS = True
CACHE_LIST = False # pointless with GitHub actions
REQUEST_METHOD = "HEAD" # HEAD gives us what we need
DEBUG = False # set to True when testing
MAX_THREADS = 150
start_time = datetime.now().isoformat()
ip_domain_map = {}
do_not_resolve = ["1.1.1.1", "127.0.0.1", "localhost", "", "0.0.0.0"] # IP addresses can't be resolved

try:
	ip_owners = json.loads(open("data/ip_owners.json").read())
except:
	ip_owners = {}
if "cloudflare" not in ip_owners:
	ip_owners["cloudflare"] = []
if "fastly" not in ip_owners:
	ip_owners["fastly"] = []

def debugmsg(msg,data="No data!"):
	if DEBUG:
		print("[DEBUG] {}".format(msg),data)

try:
	trancolist = Tranco(cache=CACHE_LIST)
	try:
		latest_list = trancolist.list()
	except:
		print("Using yesterday's list", start_time)
		yesterday = datetime.strftime(datetime.now() - timedelta(1), '%Y-%m-%d') # https://stackoverflow.com/questions/30483977/ddg#30484112
		latest_list = trancolist.list(yesterday)
	topdomains = latest_list.top(NUM_DOMAINS)
except Exception as err:
	print(err)
	topdomains = []
debugmsg(f"Got {len(topdomains)} domains (out of {NUM_DOMAINS})")
useragent = random.choice(UA_CHOICES)
headers = {"user-agent":useragent, "Connection": "keep-alive", "Sec-Fetch-Dest": "document"}
running = 0
done = 0
started = 0
cnames = []
resolver = dns.resolver.Resolver()
resolver.nameservers = ["94.140.14.140", "8.8.8.8","1.1.1.1"]
already_checked = {
	"cloudflare.com": "cloudflare",
	"cloudflare-dns.com": "cloudflare",
	"cloudflare.net": "cloudflare",
	"cloudflareinsights.com": "cloudflare",
	"amazonaws.com": "cloudfront",
	"amazontrust.com": "cloudfront",
	"amazonvideo.com": "cloudfront",
	"amzn.to": "cloudfront"
}
known_cnames = {}
known_dead = []

try:
	stats_file = json.loads(open("stats.json").read())
except:
	stats_file = {
		"date_reports": {},
		"cat_precents": {}
	}
if "cat_precents" not in stats_file:
	stats_file["cat_precents"] = {}
if "date_reports" not in stats_file:
	stats_file["date_reports"] = {}
if start_time not in stats_file["date_reports"]:
	stats_file["date_reports"][start_time] = {}

server_headers = []
via_headers = []
x_served_by = []
cache_data = []
total_domains_checked = 0

def get_cname(domain):
	global cnames
	global known_cnames
	if domain in known_cnames:
		return known_cnames[domain]
	try:
		resp = resolver.resolve(domain)
		cn = resp.canonical_name.to_text()
		if cn.endswith("."):
			cn = cn[:-1]
		known_cnames[domain] = cn
		if cn == domain:
			return None
		if cn in cnames:
			return cn
		cnames.append(cn)
		return cn
	except:
		return None

def get_ip(domain):
	global ip_domain_map
	global known_dead
	if domain in do_not_resolve:
		return []
	if domain in ip_domain_map:
		return ip_domain_map[domain]
	ips = []
	try:
		resp = resolver.resolve(domain)
		res = list(resp)
		for ip in res:
			ips.append(ip.address)
	except Exception as err:
		print(err)
		known_dead.append(domain)
	ip_domain_map[domain] = ips
	return ips

def hascloudflare(url):
	global server_headers
	global via_headers
	global x_served_by
	global already_checked
	global total_domains_checked
	global cache_data

	total_domains_checked += 1
	try:
		domain = urllib.parse.urlparse(url).netloc
		if domain in known_dead:
			return False
		if domain in already_checked:
			return already_checked[domain]

		if domain.endswith(".fastly.net"):
			return "fastly"
		if domain.endswith(".edgecastcdn.net"):
			return "edgecast"
		if domain.endswith(".akamaiedge.net") or domain.endswith(".akamai.net") or domain.endswith(".akamaitech.net"):
			return "akamai"
		if domain.endswith(".pacloudflare.com") or domain.endswith(".cloudflare.com") or domain.endswith(".cloudflare.net"):
			return "cloudflare"
		if domain.endswith(".b-cdn.net"):
			return "bunnycdn"
		if domain.endswith(".cachefly.net"):
			return "cachefly"
		if domain.endswith(".cloudfront.net"):
			return "cloudfront"
		
		ips = get_ip(domain)
		if len(ips) == 0:
			return None # don't do anything with domains which don't resolve
		for ip in ips:
			if ip in ip_owners["cloudflare"]:
				already_checked[domain] = "cloudflare"
				return "cloudflare"
			elif ip in ip_owners["fastly"]:
				return "fastly"
		cname = get_cname(domain)
		if cname != None:
			if cname in already_checked:
				return already_checked[cname]
			if cname.endswith(".fastly.net"):
				already_checked[domain] = "fastly"
				already_checked[cname] = "fastly"
				return "fastly"
			if cname.endswith(".edgecastcdn.net"):
				already_checked[domain] = "edgecast"
				already_checked[cname] = "edgecast"
				return "edgecast"
			if cname.endswith(".akamaiedge.net") or cname.endswith(".akamai.net") or cname.endswith(".akamaitech.net"):
				already_checked[cname] = "akamai"
				return "akamai"
			if cname.endswith(".pacloudflare.com") or cname.endswith(".cloudflare.com") or cname.endswith(".cloudflare.net"):
				already_checked[cname] = "cloudflare"
				return "cloudflare"
			if cname.endswith(".b-cdn.net"):
				already_checked[cname] = "bunnycdn"
				return "bunnycdn"
			if cname.endswith(".cachefly.net"):
				already_checked[cname] = "cachefly"
				return "cachefly"
			if cname.endswith(".cloudfront.net"):
				already_checked[cname] = "cloudfront"
				return "cloudfront"
		try:
			r = requests.request(url=url,method=REQUEST_METHOD,timeout=REQUEST_TIMEOUT,headers=headers)
		except:
			print("Request failed, retrying")
			r = requests.request(url=url,method=REQUEST_METHOD,timeout=REQUEST_TIMEOUT)
		debugmsg("Request done!",r.headers)
		if "Via" in r.headers:
			if r.headers["Via"] not in via_headers:
				via_headers.append(r.headers["Via"])
			if ".cloudfront.net (CloudFront)" in r.headers["Via"]:
				return "cloudfront"
		if "Server" in r.headers:
			server_header = r.headers["Server"]
			if server_header not in server_headers and server_header != None and server_header != "":
				server_headers.append(server_header)
			if server_header == None or server_header == "" or type(server_header) != str:
				pass
			elif server_header.lower() == "cloudflare" or server_header == "cloudflare-nginx":
				return "cloudflare"
			elif server_header == "AkamaiGHost" or server_header == "AkamaiNetStorage" or server_header == "akamai":
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
			elif server_header.startswith("Sucuri"):
				return "sucuri"
			elif server_header.lower() == "netlify":
				return "netlify"
			elif server_header == "Fastly":
				return "fastly"
		if "X-Server" in r.headers:
			if r.headers["x-server"] not in server_headers:
				server_headers.append(r.headers["x-server"])
			if r.headers["x-server"] == "Deflect.ca (nginx)":
				return "deflect"
		if "cache-status" in r.headers:
			if r.headers["cache-status"] not in cache_data:
				cache_data.append(r.headers['cache-status'])
			if "Netlify" in r.headers["cache-status"]:
				return "netlify"
		if "CF-RAY" in r.headers or "CF-Cache-Status" in r.headers or "cf-mitigated" in r.headers or "Cf-Mitigated" in r.headers:
			return "cloudflare"
		if "x-77-age" in r.headers or "x-77-cache" in r.headers or "x-77-nzt" in r.headers or "x-77-nzt-ray" in r.headers or "x-77-pop" in r.headers:
			return "cdn77"
		if "x-cf-reqid" in r.headers:
			return "cachefly"
		if "lswcdn_country_code" in r.headers:
			return "leaseweb"
		if "X-Sucuri-ID" in r.headers or "X-Sucuri-Cache" in r.headers or "x-sucuri-block" in r.headers:
			if "x-sucuri-block" in r.headers:
				print(dict(r.headers))
			return "sucuri"
		if "X-Cache" in r.headers:
			if r.headers['X-Cache'] not in cache_data:
				cache_data.append(r.headers['X-Cache'])
			if r.headers["X-Cache"].endswith(" from cloudfront"):
				return "cloudfront"
		if "X-Served-By" in r.headers:
			if r.headers["X-Served-By"] not in x_served_by:
				x_served_by.append(r.headers["X-Served-By"])
			if "cache-fty" in r.headers["X-Served-By"]:
				return "cachefly"
		if "Akamai-Expedia-Global-GRN" in r.headers:
			return "akamai"
		if "X-Amz-Cf-Pop" in r.headers or "X-Amz-Cf-Id" in r.headers:
			return "cloudfront"
		if "X-Fastly-Request-ID" in r.headers or "fastly-restarts" in r.headers:
			return "fastly"
		if "x-deflect-cache" in r.headers or "x-deflect-edge" in r.headers:
			return "deflect"
		if "x-ezoic-cdn" in r.headers:
				return "ezoic"
		if "x-cdn" in r.headers:
			print(r.headers["x-cdn"])
			if r.headers["x-cdn"] == "Imperva":
				return "imperva"
		if "x-incap-sess-cookie-hdr" in r.headers or "x-iinfo" in r.headers:
			return "imperva"
		if "x-nf-request-id" in r.headers:
			return "netlify"
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
		"edgecast": {
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
		},
		"deflect": {
			"domains": [],
			"ips": []
		},
		"ezoic": {
			"domains": [],
			"ips": []
		},
		"incapsula": {
			"domains": [],
			"ips": []
		},
		"netlify": {
			"domains": [],
			"ips": []
		},
	},
	"has_nothing": 0,
	"tested": 0,
	"total": 0,
	"erroredout": 0
}
full_report = {
}

def save_statdata():
	stat_data = open("stats.txt", 'w', encoding="UTF-8")
	stat_data.write(f"{total_domains_checked} domains checked. {len(already_checked)} unique domains. {len(known_dead)} dead (did not resolve).")
	stat_data.close()
	known_dead_out = open("dead.txt", 'w', encoding="UTF-8")
	known_dead_out.write("\n".join(known_dead))
	known_dead_out.close()
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
def savex_served_byheaders():
	xsbfile = open("x_served_by.txt", 'w', encoding="UTF-8")
	xsbfile.write("\n".join(x_served_by))
	xsbfile.close()
def savereport():
	global stats_file
	print(full_report)
	for cata in full_report:
		try:
			try:
				os.mkdir(cata)
			except Exception as err:
				print(err)
			report = full_report[cata]
			if cata not in stats_file["cat_precents"]:
				stats_file["cat_precents"][cata] = {}
			
			for cdn in report["cdns"]:
				if cdn not in stats_file["cat_precents"][cata]:
					stats_file["cat_precents"][cata][cdn] = []
				stats_file["cat_precents"][cata][cdn].append(len(report["cdns"][cdn]["domains"]))
				try:
					domainsfile = open(f"{cata}/{cdn}_domains.txt",'w',encoding="UTF-8")
					domainsfile.write("\n".join(sorted(report["cdns"][cdn]["domains"])))
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
				alldomains = "\n".join(sorted(report["cdns"][cdn]["domains"]))
				report_contents += f"""
{len(report["cdns"][cdn]["domains"])} used {cdn} ({(len(report["cdns"][cdn]["domains"])/dtested)*100}%):
```
{alldomains}
```
"""
			reportfile = open(os.path.join(cata, "report.md"),'w')
			reportfile.write(report_contents)
			reportfile.close()
		except Exception as err:
			print(err)
	stats_file_handle = open("stats.json", 'w')
	stats_file_handle.write(json.dumps(stats_file))
	stats_file_handle.close()

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
	already_checked[d] = httptestresult
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
	global stats_file

	if cata not in stats_file["date_reports"][start_time]:
		stats_file["date_reports"][start_time][cata] = {}
	
	running = 0
	done = 0
	started = 0
	
	full_report[cata] = copy.deepcopy(report_base)
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
	stats_file["date_reports"][start_time][cata] = full_report[cata]
	print("Done checking domains for cata",cata)

try:
	check_domains(sorted(topdomains), "top1000")
except Exception as err:
	print(err)

try:
	kdl = sorted(requests.get("https://raw.githubusercontent.com/iam-py-test/tracker_analytics/main/kdl.txt").text.split("\n"))
	check_domains(kdl, "kdl")
except Exception as err:
	print(err)

try:
	urlhaus = sorted(requests.get("https://urlhaus.abuse.ch/downloads/hostfile/").text.replace("127.0.0.1\t","").replace("\r", "").split("\n"))
	check_domains(urlhaus, "urlhaus")
except Exception as err:
	print(err)

try:
	urlshort = sorted(requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/anti-redirectors_domains.txt").text.replace("\r", "").split("\n"))
	check_domains(urlshort, "urlshort")
except Exception as err:
	print(err)

try:
	filterlists_data = json.loads(requests.get("https://raw.githubusercontent.com/collinbarrett/FilterLists/main/services/Directory/data/FilterListViewUrl.json").text)
	filterlists_domains = []
	for filterlist in filterlists_data:
		try:
			ff_domain = urllib.parse.urlparse(filterlist["url"]).netloc
			if ff_domain not in filterlists_domains:
				filterlists_domains.append(ff_domain)
		except:
			pass
	print(len(filterlists_domains))
	check_domains(sorted(filterlists_domains), "filterlists")
except Exception as err:
	print(err)

try:
	news_websites = sorted(open("data/news.txt").read().replace("\r", "").split("\n"))
	check_domains(news_websites, "news_websites")
except Exception as err:
	print(err)

try:
	usgov = sorted(open("data/usgov.txt").read().replace("\r", "").split("\n"))
	check_domains(usgov, "usgov")
except Exception as err:
	print(err)

try:
	security = sorted(open("data/security.txt").read().replace("\r", "").split("\n"))
	check_domains(security, "security")
except Exception as err:
	print(err)
try:
	invidious = sorted(open("data/invidious.txt").read().replace("\r", "").split("\n"))
	check_domains(invidious, "invidious")
except Exception as err:
	print(err)
try:
	mastodon = sorted(open("data/mastodon.txt").read().replace("\r", "").split("\n"))
	check_domains(mastodon, "mastodon")
except Exception as err:
	print(err)

savereport()
savecnames()
saveserverheaders()
saveviaheaders()
savex_served_byheaders()
save_statdata()
