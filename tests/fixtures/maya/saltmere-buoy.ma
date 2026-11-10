//Maya ASCII 2024 scene
//Name: saltmere-buoy.ma
//Codeset: UTF-8
requires maya "2024";
requires -nodeType "aiStandardSurface" "mtoa" "5.3.1";
currentUnit -l centimeter -a degree -t film;
fileInfo "application" "maya";
fileInfo "product" "Maya 2024";
fileInfo "version" "2024";
fileInfo "osv" "Linux";
createNode transform -n "Buoy";
createNode mesh -n "BuoyShape" -p "Buoy";
createNode transform -n "Pier";
createNode mesh -n "PierShape" -p "Pier";
createNode aiStandardSurface -n "BuoyRed";
createNode shadingEngine -n "BuoyRedSG";
file -rdi 1 -ns "lamp" -rfn "lampRN" "lighthouse-lamp.ma";
// End of saltmere-buoy.ma
