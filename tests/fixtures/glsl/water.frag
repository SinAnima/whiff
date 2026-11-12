#version 450
// Water surface shading.
layout(location = 0) in vec2 uv;
layout(location = 0) out vec4 colour;

layout(binding = 1) uniform sampler2D ripples;

void main()
{
    colour = vec4(0.1, 0.3, 0.6, 1.0) * texture(ripples, uv);
}
