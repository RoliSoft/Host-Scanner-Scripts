#!/bin/bash

rm -f cpe-aliases
wget https://anonscm.debian.org/viewvc/secure-testing/data/CPE/aliases\?view=co -O cpe-aliases

rm -f nmap-payloads
wget https://svn.nmap.org/nmap/nmap-payloads -O nmap-payloads

rm -f nmap-service-probes
wget https://svn.nmap.org/nmap/nmap-service-probes -O nmap-service-probes

rm -f cpe-dict.xml.gz
wget http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz -O cpe-dict.xml.gz
gzip -d cpe-dict.xml.gz

rm -f cve-items.xml
year=$(date +'%Y')
for i in $(seq 2002 $year); do
	rm -f "cve-items-$i.xml"
	wget "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-$i.xml.gz" -O "cve-items-$i.xml.gz"
	gzip -d "cve-items-$i.xml.gz"
	sed -i -r -e 's#<(/)?(vuln|cvss|cpe-lang):#<\1#g' "cve-items-$i.xml"
	cat "cve-items-$i.xml" >> cve-items.xml
	rm -f "cve-items-$i.xml"
done
awk -i inplace '/^\s*<\/nvd><\?xml/{next} NR>3&&/^\s*<nvd/{next} //{print $0}' cve-items.xml