# title: Saltmere Tides
# author: Harbour Writers
INCLUDE characters.ink
VAR lamp_lit = false
CONST HIGH_TIDE = 6
LIST weather = calm, (windy), stormy

-> pier

=== pier ===
Gulls circle the end of the pier.
* [Climb the lighthouse] -> lighthouse
* [Wait for the boats]
    The boats are late tonight.
    -> pier
+ [Listen to the bell] The bell rings twice. -> pier

=== lighthouse ===
= stairs
The stairs wind up into the dark.
- The lamp room smells of oil.
* {not lamp_lit} [Light the lamp]
    ~ lamp_lit = true
    The beam sweeps the water.
    -> ending

=== ending ===
The boats turn for home.
-> END

=== function tide_height(hour) ===
~ return hour % HIGH_TIDE
