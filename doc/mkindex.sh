#!/bin/bash

for i in *.markdown; do
	name="${i%%.*}"
	j="${i#*.}"
	num="${j%%.*}"

	echo "$name($num) $name.$num"
done > ./.index.txt

if ! diff ./index.txt ./.index.txt 2>/dev/null; then
	mv ./.index.txt ./index.txt
	echo "index.txt updated"
else
	rm -f ./.index.txt
fi

exit 0
