#!/usr/bin/env bash

if [[ -f "$1" ]]; then
	echo "Analying the logs..."
else
	echo "File Not Found"
	exit 1
fi

echo "Total number of logs: $( wc -l < "$1" )"
echo "Uniqe IPs: $( awk '{ print $1 }' "$1" | sort -u | wc -l )"
echo "Number of 2xx: $( awk ' $9 ~ /^2[0-9][0-9]$/ {print $9} ' "$1" | wc -l)"
echo "Number of 4xx: $( awk ' $9 ~ /^4[0-9][0-9]$/ {print $9} ' "$1" | wc -l)"

echo "==========================================================="
echo

echo "Top 10 Ips:"
awk '{ print $1 }' "$1" | sort | uniq -c | sort -r | head
echo

echo "Top 10 Paths:"
awk '{ print $7 }' "$1" | sort | uniq -c | sort -r | head
echo

echo "Top 10 404 Paths:"
awk ' $9==404 { print $7 }' "$1" | sort | uniq -c | sort -r | head
