module Tides where

-- | Tide model for Saltmere Harbour.
import Prelude
import Math (sin, pi)

type Gauge = { name :: String, level :: Number }

highWater :: Gauge -> Number
highWater g = g.level + 1.5 * sin (pi / 6.0)

data Basin = Inner | Outer
