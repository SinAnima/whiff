#!/bin/sed -f
# Normalise gauge names in the harbour log.
s/North Gauge/north/g
s/  */ /g
:join
/\\$/ {
  N
  s/\\\n//
  b join
}
