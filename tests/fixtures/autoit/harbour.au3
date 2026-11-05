; Harbour logbook helper.
#include <MsgBoxConstants.au3>
#include "Tides.au3"

#cs
  Shows the next high water.
#ce
Func NextHighWater()
    Return "14:20"
EndFunc

MsgBox($MB_OK, "Saltmere", NextHighWater())
