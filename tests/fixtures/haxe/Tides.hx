package saltmere;

import haxe.ds.StringMap;
using StringTools;

/**
 * Tide model for Saltmere Harbour.
 */
class Tides {
    static var gauges = new StringMap<Float>();

    public static function highWater(base:Float):Float {
        // simple harmonic model
        return base + 1.5 * Math.sin(Math.PI / 6);
    }

    static function main() {
        trace(highWater(2.0));
    }
}
