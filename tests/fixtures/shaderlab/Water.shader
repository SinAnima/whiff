// Water surface for the harbour scene.
Shader "Saltmere/Water"
{
    Properties
    {
        _Colour ("Colour", Color) = (0.1, 0.3, 0.6, 1)
        _Ripples ("Ripples", 2D) = "white" {}
    }
    SubShader
    {
        Pass
        {
            Name "Surface"
            CGPROGRAM
            #pragma vertex vert
            #pragma fragment frag
            #include "UnityCG.cginc"
            ENDCG
        }
    }
    Fallback "Diffuse"
}
