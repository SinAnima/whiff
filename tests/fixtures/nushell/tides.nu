# Tide report for Saltmere Harbour.
use std assert

# High water from a base level.
def high-water [base: float] {
    $base + 1.5
}

export def "harbour report" [] {
    open gauges.csv | each {|g| high-water $g.level }
}

alias hw = high-water
