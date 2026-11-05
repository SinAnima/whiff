// Water surface shading for the harbour scene.
#include "common.hlsli"

cbuffer Frame : register(b0)
{
    float4x4 viewProj;
    float time;
};

struct VSOut
{
    float4 pos : SV_Position;
    float2 uv : TEXCOORD0;
};

float4 main(VSOut i) : SV_Target
{
    return float4(0.1, 0.3, 0.6, 1.0) * (0.5 + 0.5 * sin(time));
}
