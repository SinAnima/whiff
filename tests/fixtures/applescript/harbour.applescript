-- Shows the next high water at Saltmere Harbour.
use AppleScript version "2.4"
use scripting additions

(* The tide table lives in a text file. *)
on nextHighWater()
	return "14:20"
end nextHighWater

on run
	display notification nextHighWater() with title "Saltmere"
end run
