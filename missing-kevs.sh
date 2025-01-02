#!/bin/zsh
# Usage: check infile.txt for all mentioned CVEs. Then get the latest KEV, and check to see
# if there are any mentioned in infile.txt isn't on KEV.

grep -Eo 'CVE-[0-9]{4}-[0-9]{4,7}' infile.txt | sort | uniq | \
  comm -23 - <(curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  grep -Eo 'CVE-[0-9]{4}-[0-9]{4,7}' | sort | uniq) | \
  awk '{print "[*] Missing: " $1 " not on KEV!"}'
