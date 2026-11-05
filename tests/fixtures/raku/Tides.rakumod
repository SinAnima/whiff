# Tide model for Saltmere Harbour.
use v6.d;
use JSON::Fast;

unit module Tides;

class Gauge is export {
    has Str $.name;
    has Num $.level;
}

sub high-water(Gauge $g --> Num) is export {
    $g.level + 1.5e0 * sin(pi / 6)
}
