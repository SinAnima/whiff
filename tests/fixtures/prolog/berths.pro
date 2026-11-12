% Berth rules for Saltmere Harbour.
:- module(berths, [berth/2]).
:- use_module(library(lists)).

vessel(gull, 12).
vessel(tern, 34).

/* Large vessels use the outer quay. */
berth(Name, outer) :- vessel(Name, Length), Length > 30.
berth(Name, inner) :- vessel(Name, Length), Length =< 30.
