// Tide model for the harbour map.
enable f16;

struct Gauge {
    level: f32,
}

@group(0) @binding(0) var<storage, read_write> gauges: array<Gauge>;

fn high_water(base: f32) -> f32 {
    return base + 1.5 * sin(3.14159 / 6.0);
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    gauges[id.x].level = high_water(gauges[id.x].level);
}
