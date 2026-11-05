; Tide model, compiled for the harbour gauge.
target datalayout = "e-m:e-i64:64-n32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.Gauge = type { double }

@amplitude = global double 1.500000e+00

declare double @sin(double)

define double @high_water(double %base) {
entry:
  %s = call double @sin(double 0x3FE0C152382D7365)
  %a = load double, ptr @amplitude
  %m = fmul double %a, %s
  %r = fadd double %base, %m
  ret double %r
}
