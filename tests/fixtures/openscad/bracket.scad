// Saltmere mooring bracket
use <bolts.scad>
function hole_x(i) = -12 + 24 * i;
difference() {
  cube([40, 20, 6], center = true);
  for (i = [0, 1]) translate([hole_x(i), 0, 0]) cylinder(h = 10, r = 2.5, center = true);
}
