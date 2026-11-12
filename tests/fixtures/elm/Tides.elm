module Tides exposing (highWater, Gauge)

{-| Tide model for Saltmere Harbour. -}

import Html exposing (text)


type alias Gauge =
    { name : String, level : Float }


highWater : Gauge -> Float
highWater g =
    -- simple harmonic model
    g.level + 1.5 * sin (pi / 6)


main =
    text (String.fromFloat (highWater { name = "north", level = 2.0 }))
