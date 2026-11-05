# Tide report for Saltmere Harbour.
use str
use math

var amplitude = 1.5

fn high-water {|base|
  + $base $amplitude
}

echo (high-water 2.0)
