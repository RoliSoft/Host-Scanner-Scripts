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

rm -f cve-items.xml.gz
wget https://cve.mitre.org/data/downloads/allitems.xml.gz -O cve-items.xml.gz
gzip -d cve-items.xml.gz