#!/usr/bin/env bash

if [[ -f "$1" ]]; then
	echo "Analying the logs..."
else
	echo "File Not Found"
	return 1
fi

echo "Total number of logs: $( cat $1 | wc -l )"
