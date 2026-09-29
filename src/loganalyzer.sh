#!/usr/bin/env bash

n=10 #default vaule for dipslaying top
threshold=60
status=""

usage () {
cat <<USAGE
Usage: $(basename "$0") [-n N] [-s CLASS] [-h] [file]
  -n N     show top N rows (default: 10)
  -s CLASS only analyse requests with this status class (2xx, 3xx, 4xx, 5xx)
  -h       show this help
USAGE
}

# --- colors -----------------------------------------------------------------
# Only emit ANSI codes when stdout is a terminal and NO_COLOR isn't set.
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
	BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'
	RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'
	BLUE=$'\e[34m'; CYAN=$'\e[36m'
else
	BOLD=''; DIM=''; RESET=''
	RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''
fi

rule()    { printf '%s═══════════════════════════════════════════════════════════%s\n' "$DIM" "$RESET"; }
heading() { printf '\n%s%s%s\n' "$BOLD$CYAN" "$1" "$RESET"; }

while getopts ":n:s:h" opt; do
	case "$opt" in
		n) n=${OPTARG} ;;
		s) status=${OPTARG} ;;
		h) usage; exit 0 ;;
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
	printf '%sAnalysing %s ...%s\n' "$DIM" "$1" "$RESET"
else
	printf '%sFile Not Found%s\n' "$RED" "$RESET"
	exit 1
fi

data=$(mktemp)
trap 'rm -f "$data"' EXIT

awk -v cls="${status:0:1}" 'cls == "" || substr($9, 1, 1) == cls' "$1" > "$data"

if [[ ! -s $data ]]; then
	printf '%sNo requests matched -s %s%s\n' "$YELLOW" "$status" "$RESET"
	exit 0
fi

# --- summary ----------------------------------------------------------------
total=$(   wc -l < "$data" )
uniq_ips=$( awk '{ print $1 }' "$data" | sort -u | wc -l )
n2xx=$( awk '$9 ~ /^2[0-9][0-9]$/' "$data" | wc -l )
n3xx=$( awk '$9 ~ /^3[0-9][0-9]$/' "$data" | wc -l )
n4xx=$( awk '$9 ~ /^4[0-9][0-9]$/' "$data" | wc -l )
n5xx=$( awk '$9 ~ /^5[0-9][0-9]$/' "$data" | wc -l )

echo
rule
printf '%s  Log Analysis Report%s\n' "$BOLD" "$RESET"
[[ -n $status ]] && printf '%s  Filter: only %s requests%s\n' "$DIM" "$status" "$RESET"
rule

heading "Overview"
printf '  %-16s %s%9d%s\n' "Total requests" "$BOLD"   "$total"    "$RESET"
printf '  %-16s %s%9d%s\n' "Unique IPs"     "$BOLD"   "$uniq_ips" "$RESET"
printf '  %-16s %s%9d%s\n' "2xx success"    "$GREEN"  "$n2xx"     "$RESET"
printf '  %-16s %s%9d%s\n' "3xx redirect"   "$CYAN"   "$n3xx"     "$RESET"
printf '  %-16s %s%9d%s\n' "4xx client err" "$YELLOW" "$n4xx"     "$RESET"
printf '  %-16s %s%9d%s\n' "5xx server err" "$RED"    "$n5xx"     "$RESET"

heading "Top $n IPs"
awk '{ print $1 }' "$data" | sort | uniq -c | sort -rn | head -n "$n" |
	awk -v col="$GREEN" -v r="$RESET" '{ printf "  %s%6d%s  %s\n", col, $1, r, $2 }'

heading "Top $n Paths"
awk '{ print $7 }' "$data" | sort | uniq -c | sort -rn | head -n "$n" |
	awk -v col="$BLUE" -v r="$RESET" '{ printf "  %s%6d%s  %s\n", col, $1, r, $2 }'

heading "Top $n 404 Paths"
awk '$9==404 { print $7 }' "$data" | sort | uniq -c | sort -rn | head -n "$n" |
	awk -v col="$YELLOW" -v r="$RESET" '{ printf "  %s%6d%s  %s\n", col, $1, r, $2 }'

heading "Requests per Hour"
awk -F: -v d="$DIM" -v r="$RESET" -v b="$BOLD" -v cyan="$CYAN" '
{ count[$2]++ }
END {
	max = 0
	for (h in count) if (count[h] > max) max = count[h]
	for (h = 0; h < 24; h++) {
		hh = sprintf("%02d", h)
		c = count[hh] + 0
		bars = (max > 0) ? int(c * 40 / max) : 0
		bar = ""
		for (i = 0; i < bars; i++) bar = bar "#"
		printf "  %s%sh%s  %s%5d%s  %s%s%s\n", d, hh, r, b, c, r, cyan, bar, r
	}
}' "$data"


heading "Suspicious activity (> $threshold requests/min from one IP)"
suspicious=$(awk -v limit="$threshold" '
{ m = substr($4, 2, 17); count[$1 " " m]++ }
END { for (k in count) if (count[k] > limit) print count[k], k }
' "$data" | sort -rn | head -n "$n")

if [[ -z $suspicious ]]; then
	printf '  %sNone detected%s\n' "$GREEN" "$RESET"
else
	awk -v col="$RED" -v d="$DIM" -v r="$RESET" '
	{ printf "  %s%6d%s  %-16s %s%s%s\n", col, $1, r, $2, d, $3, r }
	' <<< "$suspicious"
fi
