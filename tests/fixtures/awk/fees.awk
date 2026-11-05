#!/usr/bin/awk -f
# Sum berth fees per vessel from a CSV log.
BEGIN { FS = "," }

function fee(length) {
    return length * 8
}

{ total[$1] += fee($2) }

END {
    for (v in total) print v, total[v]
}
