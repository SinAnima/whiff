## Tide predictions for Saltmere Harbour.
import std/[math, strutils]
from times import now

type
  Gauge* = object
    name*: string
    level: float

proc highWater*(g: Gauge): float =
  # Simple harmonic model.
  g.level + 1.5 * sin(PI / 6.0)

template log(msg: string) = echo msg

when isMainModule:
  log $highWater(Gauge(name: "north", level: 2.0))
