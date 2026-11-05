--  Tide model for Saltmere Harbour.
with Ada.Text_IO;
with Ada.Numerics.Elementary_Functions;

package body Tides is
   use Ada.Numerics.Elementary_Functions;

   type Level is new Float;

   function High_Water (Base : Float) return Float is
   begin
      return Base + 1.5 * Sin (3.14159 / 6.0);
   end High_Water;

   procedure Report is
   begin
      Ada.Text_IO.Put_Line (Float'Image (High_Water (2.0)));
   end Report;
end Tides;
