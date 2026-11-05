# Berth booking policy for Saltmere Harbour.
package harbour.berths

import rego.v1

default allow := false

max_length := 30

allow if {
    input.vessel.length <= max_length
}

deny contains msg if {
    input.vessel.length > 60
    msg := "vessel too long for the harbour"
}
