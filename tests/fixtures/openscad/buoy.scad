// Saltmere buoy
// CC0, Saltmere Harbour Office
$fn = 48;
module buoy(r = 6) {
  cylinder(h = 14, r = r);
  translate([0, 0, 14]) cylinder(h = 8, r1 = r * 0.7, r2 = 0);
}
buoy();
