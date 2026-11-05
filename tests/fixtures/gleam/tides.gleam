//// Tide model for Saltmere Harbour.

import gleam/float
import gleam/io

pub type Gauge {
  Gauge(name: String, level: Float)
}

const amplitude = 1.5

/// High water from a gauge's base level.
pub fn high_water(g: Gauge) -> Float {
  g.level +. amplitude
}

pub fn main() {
  io.println(float.to_string(high_water(Gauge("north", 2.0))))
}
