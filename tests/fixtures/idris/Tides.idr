-- Tide arithmetic for Saltmere Harbour.
module Tides

import Data.Nat

||| A gauge reading in centimetres.
record Reading where
  constructor MkReading
  level : Nat

highWater : Reading -> Nat
highWater r = level r + 150
