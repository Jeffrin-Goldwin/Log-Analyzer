#!/usr/bin/env bash

n=10 #default vaule for dipslaying top
status=""

usage () {
cat <<USAGE
Usage: $(basename "$0") [-n N] [-h] [file]
  -n N     show top N rows (default: 10)
  -s CLASS only analyse request with this status class
  -h       show this help
USAGE
}

while getopts ":n:s:h" opt; do
	case "$opt" in
		n)
			n=${OPTARG} ;;
		s)
			status=${OPTARG} ;;
		h)
			usage
			exit 0 ;;
		:)
			echo "Error: -$OPTARG needs a value" >&2
			usage >&2
			exit 1 ;;
		\?)
			echo "Error: unknown option -$OPTARG" >&2
			usage >&2
			exit 1 ;;
	esac
done

if ! [[ $n =~ ^[1-9][0-9]*$ ]]; then
	echo "Error: -n must be a positive whole number, got '$n'" >&2
	exit 1
fi

if [[ -n $status && ! $status =~ ^[2-5]xx$ ]]; then
	echo "Error: -s must be one of 2xx, 3xx, 4xx, 5xx, got '$status'" >&2
	exit 1
fi

shift $((OPTIND -1))

if [[ -f "$1" ]]; then
	echo "Analying the logs..."
else
	echo "File Not Found"
	exit 1
fi

data=$(mktemp)
trap 'rm -f "$data"' EXIT

awk -v cls="${status:0:1}" 'cls == "" || substr($9, 1, 1) == cls' "$1" > "$data"

if [[ ! -s $data ]]; then
	echo "No requests matched -s $status"
	exit 0
fi

[[ -n $status ]] && echo "Filter: only $status requests"

echo "Total number of logs: $( wc -l < "$data" )"
echo "Uniqe IPs: $( awk '{ print $1 }' "$data" | sort -u | wc -l )"
echo "Number of 2xx: $( awk ' $9 ~ /^2[0-9][0-9]$/ {print $9} ' "$data" | wc -l)"
echo "Number of 4xx: $( awk ' $9 ~ /^4[0-9][0-9]$/ {print $9} ' "$data" | wc -l)"

echo "==========================================================="
echo

echo "Top $n Ips:"
awk '{ print $data }' "$data" | sort | uniq -c | sort -rn | head -n $n
echo

echo "Top $n Paths:"
awk '{ print $7 }' "$data" | sort | uniq -c | sort -rn | head -n $n
echo

echo "Top $n 404 Paths:"
awk ' $9==404 { print $7 }' "$data" | sort | uniq -c | sort -rn | head -n $n


echo
echo "==========================================================="
echo

echo "Request Per Hour:"
awk -F: '{ count[$2]++ }
END {
  for (h in count) {
    bar = ""
    for (i = 0; i < count[h] / 10; i++) bar = bar "#"
    printf "%s  %4d  %s\n", h, count[h], bar
  }
}' "$data" | sort -n
