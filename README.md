# Cloudflare usage tracker
Track the usage of Cloudflare (and a few other similar services)

This project looks for:
- CloudFlare (of course)
- CloudFront (Amazon)
- Akamai
- BunnyCDN
- DDoSGuard
- MyraCloud (Myra Security)
- Sucuri
- Fastly
- Cachefly
- CDN77
- keycdn
- leaseweb

Not all these CDNs are as bad as CloudFlare.

## Structure
- [top1000](./top1000/report.md)

Tracks the top 1000 most popular domains [in the Tranco list](https://tranco-list.eu/)
- [kdl](./kdl/report.md)

Tracks the domains present on the top 200 domains ([based on data from my Tracker Analytics project](https://github.com/iam-py-test/tracker_analytics/))
- [urlhaus](./urlhaus/report.md)

Tracks [websites distributing malware, using data from abuse.ch's URLHaus](https://urlhaus.abuse.ch/)
- [URL Shorteners](./urlshort/report.md)

Tracks URL Shorteners, based on my own data.
- [Filterlists](./filterlists/report.md)

Tracks how many filterlists are hosted behind CloudFlare, [using the data from filterlists.com](https://filterlists.com/) (Behind CloudFlare).

- [News websites](./news_websites/report.md)

[Tracks news websites](./data/news.txt)

- [United States government](./us_gov/report.md)

[Tracks US government (federal, state, local, territorial, and tribal) websites](./data/usgov.txt)

- [Cybersecurity](./security/report.md)

[Tracks cybersecurity companies and websites](./data/security.txt)
