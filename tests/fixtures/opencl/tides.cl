// Tide model kernel for Saltmere Harbour.
#include "gauge.h"

/* One work item per gauge. */
__kernel void high_water(__global const float *base, __global float *out)
{
    int i = get_global_id(0);
    out[i] = base[i] + 1.5f * sin(M_PI_F / 6.0f);
}
