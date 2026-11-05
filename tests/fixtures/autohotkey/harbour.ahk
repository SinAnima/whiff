; Hotkeys for the harbour logbook.
#Requires AutoHotkey v2.0
#Include lib\Tides.ahk

/*
  Ctrl+Alt+T types the next high water.
*/
^!t::Send(NextHighWater())

NextHighWater() {
    return "14:20"
}
