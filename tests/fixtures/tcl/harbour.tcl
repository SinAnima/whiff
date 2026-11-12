#!/usr/bin/env tclsh
# Berth report for Saltmere Harbour.
package require Tcl 8.6
package provide harbour 1.0

namespace eval harbour {
    variable berths 12
}

proc harbour::allocate {length} {
    # Large vessels use the outer quay.
    if {$length > 30} { return outer }
    return inner
}

puts [harbour::allocate 34]
