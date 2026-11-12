// Gauge report script.
module main

import os
import math

struct Gauge {
	name  string
	level f64
}

fn (g Gauge) high_water() f64 {
	return g.level + 1.5 * math.sin(math.pi / 6)
}

fn main() {
	g := Gauge{'north', 2.0}
	println(g.high_water())
}
