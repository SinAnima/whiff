(* Bilge pump control for the harbour pontoon. *)
FUNCTION_BLOCK FB_TidePump
VAR_INPUT
    Level : REAL; // metres
END_VAR
VAR_OUTPUT
    PumpOn : BOOL;
END_VAR
    PumpOn := Level > 3.5;
END_FUNCTION_BLOCK

PROGRAM MAIN
VAR
    pump : FB_TidePump;
END_VAR
    pump(Level := 2.0);
END_PROGRAM
