NB. Tide model for Saltmere Harbour (levels in cm).
require 'stats/base'
coclass 'tides'

amplitude =: 150
highwater =: 3 : 'y + amplitude'
mean =: +/ % #
