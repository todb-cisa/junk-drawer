#!/bin/zsh

grep -Eo 'CVE-[0-9]{4}-[0-9]{4,7}' infile.txt | sort | uniq | \
  comm -23 - <(curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  grep -Eo 'CVE-[0-9]{4}-[0-9]{4,7}' | sort | uniq) | \
  awk '{print "[*] Missing: " $1 " not on KEV!"}'
