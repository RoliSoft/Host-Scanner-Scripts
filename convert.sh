#!/bin/bash

if [[ $1 == "-h" || $1 == "--help" ]]; then
	echo usage: convert [script] [--nogz] [--json]; exit 0
fi

if [[ $1 != --* ]]; then
	scr=$1; shift
fi

if [[ $1 == "--nogz" ]]; then
	gz=0; shift
else
	gz=1
fi

if [[ -z ${scr} || ${scr} == "cpealt" ]] && [[ -f cpe-aliases ]]; then
	rm -f cpe-aliases.dat cpe-aliases.dat.gz
	go run cpealt2hs.go $@ cpe-aliases cpe-aliases.dat
	[[ ${gz} -eq 1 ]] && gzip -9 cpe-aliases.dat
fi

if [[ -z ${scr} || ${scr} == "nudp" ]] && [[ -f nmap-payloads ]]; then
	rm -f payloads-nmap.dat payloads-nmap.dat.gz
	go run nudp2hs.go $@ nmap-payloads payloads-nmap.dat
	[[ ${gz} -eq 1 ]] && gzip -9 payloads-nmap.dat
fi

if [[ -z ${scr} || ${scr} == "zudp" ]] && [[ -d zmap/examples/udp-probes ]]; then
	rm -f payloads-zmap.dat payloads-zmap.dat.gz
	go run zudp2hs.go $@ zmap/examples/udp-probes payloads-zmap.dat
	[[ ${gz} -eq 1 ]] && gzip -9 payloads-zmap.dat
fi

if [[ -z ${scr} || ${scr} == "ncpe" ]] && [[ -f nmap-service-probes ]]; then
	rm -f cpe-regex-nmap.dat cpe-regex-nmap.dat.gz
	go run ncpe2hs.go $@ nmap-service-probes cpe-regex-nmap.dat
	[[ ${gz} -eq 1 ]] && gzip -9 cpe-regex-nmap.dat
fi

if [[ -z ${scr} || ${scr} == "cpe" ]] && [[ -f cpe-dict.xml ]]; then
	rm -f cpe-list.dat cpe-list.dat.gz
	go run cpe2hs.go $@ cpe-dict.xml cpe-list.dat
	[[ ${gz} -eq 1 ]] && gzip -9 cpe-list.dat
fi

if [[ -z ${scr} || ${scr} == "cve" ]] && [[ -f cve-items.xml ]]; then
	rm -f cve-list.dat cve-list.dat.gz
	go run cve2hs.go $@ cve-items.xml cve-list.dat
	[[ ${gz} -eq 1 ]] && gzip -9 cve-list.dat
fi