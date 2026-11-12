/// Tide tables for Saltmere Harbour.
module saltmere.tides;

import std.stdio;
import std.math : sin, PI;

struct Reading
{
    double level; // metres
}

double highWater(double base) pure nothrow
{
    return base + 1.5 * sin(PI / 6);
}

void main()
{
    writeln(highWater(2.0));
}
