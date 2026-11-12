# Tide gauge node for the harbour scene.
class_name TideGauge
extends Node2D

signal level_changed(level: float)

const Ripple = preload("res://ripple.gd")

@export var amplitude: float = 1.5
var level := 0.0

func _process(delta: float) -> void:
	level = amplitude * sin(Time.get_ticks_msec() / 1000.0)
	level_changed.emit(level)
