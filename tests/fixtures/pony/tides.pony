// Tide model for Saltmere Harbour.
use "math"

actor Main
  new create(env: Env) =>
    env.out.print(Tides.high_water(2.0).string())

primitive Tides
  fun high_water(base: F64): F64 =>
    base + 1.5
