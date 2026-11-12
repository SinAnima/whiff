# Tide model for Saltmere Harbour.
module [high_water]

import Num

high_water : F64 -> F64
high_water = \base ->
    # simple harmonic model
    base + 1.5
