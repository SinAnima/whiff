// Tide model for Saltmere Harbour.
open Belt

type gauge = {name: string, level: float}

@module("./sine") external sine: float => float = "sine"

let highWater = g => g.level +. 1.5 *. sine(3.14159 /. 6.)

module Basin = {
  let berths = 12
}
