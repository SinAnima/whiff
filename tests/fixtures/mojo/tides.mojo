# Tide model for Saltmere Harbour.
from math import sin, pi

@value
struct Gauge:
    var name: String
    var level: Float64

fn high_water(g: Gauge) -> Float64:
    """High water from the base level."""
    return g.level + 1.5 * sin(pi / 6)

def main():
    print(high_water(Gauge("north", 2.0)))
