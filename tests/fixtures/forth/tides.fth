\ Tide model for Saltmere Harbour (levels in cm).
150 constant amplitude
variable base-level

: high-water ( base -- hw )  amplitude + ;
: report ( -- )  base-level @ high-water . ;

200 base-level !
report
