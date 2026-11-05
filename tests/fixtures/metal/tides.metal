// Tide model for the harbour map.
#include <metal_stdlib>
using namespace metal;

struct Gauge {
    float level;
};

kernel void high_water(device Gauge *gauges [[buffer(0)]], uint id [[thread_position_in_grid]])
{
    gauges[id].level += 1.5 * sin(M_PI_F / 6.0);
}
