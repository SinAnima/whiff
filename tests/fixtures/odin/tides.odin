// Tide model for Saltmere Harbour.
package tides

import "core:fmt"
import "core:math"

Gauge :: struct {
	name:  string,
	level: f64,
}

high_water :: proc(g: Gauge) -> f64 {
	return g.level + 1.5 * math.sin(math.PI / 6)
}

main :: proc() {
	fmt.println(high_water(Gauge{"north", 2.0}))
}
