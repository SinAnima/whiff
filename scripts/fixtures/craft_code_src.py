"""Source files for the stage 8 code fixtures (one per language), written
by hand for the fictitious Saltmere Harbour, CC0-1.0. Imported by
craft_code.py; kept apart so the manifests and the sources stay readable.

Each entry: format id -> [(file name, text)].
"""

SOURCES = {
    "astro": [("TideCard.astro", """---
// Tide card for the harbour dashboard.
import Layout from '../layouts/Layout.astro';
import { formatTide } from '../lib/tides';
const { station } = Astro.props;
---
<Layout title="Saltmere tides">
  <!-- one card per gauge -->
  <TideTable station={station} />
</Layout>
<style>
  h1 { color: navy; }
</style>
""")],
    "nim": [("tides.nim", """## Tide predictions for Saltmere Harbour.
import std/[math, strutils]
from times import now

type
  Gauge* = object
    name*: string
    level: float

proc highWater*(g: Gauge): float =
  # Simple harmonic model.
  g.level + 1.5 * sin(PI / 6.0)

template log(msg: string) = echo msg

when isMainModule:
  log $highWater(Gauge(name: "north", level: 2.0))
""")],
    "crystal": [("harbour.cr", """# Harbour berth allocation.
require "json"
require "./berth"

module Saltmere
  class Harbour
    def initialize(@name : String)
    end

    def berths : Int32
      12
    end
  end
end

puts Saltmere::Harbour.new("Saltmere").berths
""")],
    "d": [("tides.d", """/// Tide tables for Saltmere Harbour.
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
""")],
    "vlang": [("gauge.vsh", """// Gauge report script.
module main

import os
import math

struct Gauge {
	name  string
	level f64
}

fn (g Gauge) high_water() f64 {
	return g.level + 1.5 * math.sin(math.pi / 6)
}

fn main() {
	g := Gauge{'north', 2.0}
	println(g.high_water())
}
""")],
    "odin": [("tides.odin", """// Tide model for Saltmere Harbour.
package tides

import "core:fmt"
import "core:math"

Gauge :: struct {
	name:  string,
	level: f64,
}

high_water :: proc(g: Gauge) -> f64 {
	return g.level + 1.5 * math.sin(math.PI / 6)
}

main :: proc() {
	fmt.println(high_water(Gauge{"north", 2.0}))
}
""")],
    "fortran": [("tides.f90", """! Tide model for Saltmere Harbour.
module tides
  implicit none
contains
  ! High water from a base level.
  pure real function high_water(base)
    real, intent(in) :: base
    high_water = base + 1.5 * sin(3.14159 / 6.0)
  end function high_water
end module tides

program harbour
  use tides
  implicit none
  print *, high_water(2.0)
end program harbour
""")],
    "cobol": [("BERTHS.cbl", """      * Berth fees for Saltmere Harbour.
       IDENTIFICATION DIVISION.
       PROGRAM-ID. BERTHS.
       ENVIRONMENT DIVISION.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       COPY FEES.
       01 WS-LENGTH PIC 9(3) VALUE 12.
       01 WS-FEE    PIC 9(5) VALUE 0.
       PROCEDURE DIVISION.
       MAIN-PARA.
           COMPUTE WS-FEE = WS-LENGTH * 8
           DISPLAY "FEE: " WS-FEE
           STOP RUN.
""")],
    "pascal": [("Tides.pas", """{ Tide tables for Saltmere Harbour. }
unit Tides;

interface

uses
  SysUtils,
  Math;

type
  TGauge = record
    Name: string;
    Level: Double;
  end;

function HighWater(const G: TGauge): Double;

implementation

// Simple harmonic model.
function HighWater(const G: TGauge): Double;
begin
  Result := G.Level + 1.5 * Sin(Pi / 6);
end;

end.
""")],
    "ada": [("tides.adb", """--  Tide model for Saltmere Harbour.
with Ada.Text_IO;
with Ada.Numerics.Elementary_Functions;

package body Tides is
   use Ada.Numerics.Elementary_Functions;

   type Level is new Float;

   function High_Water (Base : Float) return Float is
   begin
      return Base + 1.5 * Sin (3.14159 / 6.0);
   end High_Water;

   procedure Report is
   begin
      Ada.Text_IO.Put_Line (Float'Image (High_Water (2.0)));
   end Report;
end Tides;
""")],
    "lisp": [("harbour.lisp", """;;;; Berth allocation for Saltmere Harbour.
(defpackage :saltmere
  (:use :cl)
  (:export #:allocate))
(in-package :saltmere)

(defparameter *berths* 12 "Berths in the inner basin.")

#| Berths are numbered
   from the harbour mouth. |#
(defstruct vessel name length)

(defun allocate (vessel)
  "Return a berth for VESSEL."
  (if (> (vessel-length vessel) 30) 1 2))

(defmacro with-harbour (&body body)
  `(progn ,@body))
"""), ("harbour-mode.el", """;;; harbour-mode.el --- Saltmere Harbour notes  -*- lexical-binding: t -*-
(require 'cl-lib)

(defcustom harbour-berths 12
  "Number of berths."
  :type 'integer)

(defun harbour-tide ()
  "Show the next tide."
  (interactive)
  (message "High water at 14:20"))

(provide 'harbour-mode)
;;; harbour-mode.el ends here
""")],
    "scheme": [("tides.rkt", """#lang racket
;; Tide model for Saltmere Harbour.
(require racket/math)

(struct gauge (name level))

(define (high-water g)
  (+ (gauge-level g) (* 1.5 (sin (/ pi 6)))))

#| Example:
   (high-water (gauge "north" 2.0)) |#
(define-syntax-rule (report e) (displayln e))

(report (high-water (gauge "north" 2.0)))
""")],
    "prolog": [("berths.pro", """% Berth rules for Saltmere Harbour.
:- module(berths, [berth/2]).
:- use_module(library(lists)).

vessel(gull, 12).
vessel(tern, 34).

/* Large vessels use the outer quay. */
berth(Name, outer) :- vessel(Name, Length), Length > 30.
berth(Name, inner) :- vessel(Name, Length), Length =< 30.
""")],
    "elm": [("Tides.elm", """module Tides exposing (highWater, Gauge)

{-| Tide model for Saltmere Harbour. -}

import Html exposing (text)


type alias Gauge =
    { name : String, level : Float }


highWater : Gauge -> Float
highWater g =
    -- simple harmonic model
    g.level + 1.5 * sin (pi / 6)


main =
    text (String.fromFloat (highWater { name = "north", level = 2.0 }))
""")],
    "purescript": [("Tides.purs", """module Tides where

-- | Tide model for Saltmere Harbour.
import Prelude
import Math (sin, pi)

type Gauge = { name :: String, level :: Number }

highWater :: Gauge -> Number
highWater g = g.level + 1.5 * sin (pi / 6.0)

data Basin = Inner | Outer
""")],
    "rescript": [("Tides.res", """// Tide model for Saltmere Harbour.
open Belt

type gauge = {name: string, level: float}

@module("./sine") external sine: float => float = "sine"

let highWater = g => g.level +. 1.5 *. sine(3.14159 /. 6.)

module Basin = {
  let berths = 12
}
"""), ("Tides.resi", """// Interface for Tides.
type gauge = {name: string, level: float}
let highWater: gauge => float
""")],
    "coffeescript": [("harbour.coffee", """# Berth allocation for Saltmere Harbour.
{readFile} = require 'fs'
tides = require './tides'

###
Berths are numbered from the mouth.
###
class Harbour
  constructor: (@name) ->
  berths: -> 12

allocate = (vessel) ->
  if vessel.length > 30 then 1 else 2

console.log new Harbour('Saltmere').berths()
""")],
    "haxe": [("Tides.hx", """package saltmere;

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
""")],
    "tcl": [("harbour.tcl", """#!/usr/bin/env tclsh
# Berth report for Saltmere Harbour.
package require Tcl 8.6
package provide harbour 1.0

namespace eval harbour {
    variable berths 12
}

proc harbour::allocate {length} {
    # Large vessels use the outer quay.
    if {$length > 30} { return outer }
    return inner
}

puts [harbour::allocate 34]
""")],
    "awk": [("fees.awk", """#!/usr/bin/awk -f
# Sum berth fees per vessel from a CSV log.
BEGIN { FS = "," }

function fee(length) {
    return length * 8
}

{ total[$1] += fee($2) }

END {
    for (v in total) print v, total[v]
}
""")],
    "sed": [("tidy.sed", """#!/bin/sed -f
# Normalise gauge names in the harbour log.
s/North Gauge/north/g
s/  */ /g
:join
/\\\\$/ {
  N
  s/\\\\\\n//
  b join
}
""")],
    "solidity": [("BerthRegistry.sol", """// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import "./Ownable.sol";

/// @title Berth registry for Saltmere Harbour (a teaching example).
contract BerthRegistry is Ownable {
    mapping(uint256 => string) public berths;

    event Assigned(uint256 berth, string vessel);

    modifier validBerth(uint256 b) {
        require(b < 12, "no such berth");
        _;
    }

    function assign(uint256 b, string calldata vessel) external onlyOwner validBerth(b) {
        berths[b] = vessel;
        emit Assigned(b, vessel);
    }
}
""")],
    "move": [("berths.move", """// Berth registry for Saltmere Harbour.
module saltmere::berths {
    use std::string::String;
    use sui::table::Table;

    /// A berth and its vessel.
    public struct Berth has store {
        number: u64,
        vessel: String,
    }

    public fun number(b: &Berth): u64 {
        b.number
    }
}
""")],
    "cairo": [("berths.cairo", """// Berth counter for Saltmere Harbour.
use core::num::traits::Zero;

#[derive(Drop)]
struct Berth {
    number: u32,
}

trait BerthTrait {
    fn is_inner(self: @Berth) -> bool;
}

fn main() {
    let b = Berth { number: 3 };
    println!("{}", b.number);
}
""")],
    "vyper": [("berths.vy", """# pragma version ^0.4.0
\"\"\"
@title Berth registry for Saltmere Harbour
\"\"\"
from ethereum.ercs import IERC20

struct Berth:
    number: uint256
    vessel: String[32]

event Assigned:
    number: uint256

berths: public(HashMap[uint256, Berth])

@external
def assign(n: uint256, vessel: String[32]):
    self.berths[n] = Berth(number=n, vessel=vessel)
    log Assigned(n)
""")],
    "verilog": [("tide_counter.v", """// Tide pulse counter for the Saltmere gauge.
`timescale 1ns / 1ps
`include "gauge_defs.vh"

module tide_counter (
    input  wire       clk,
    input  wire       pulse,
    output reg  [7:0] count
);
    always @(posedge clk) begin
        if (pulse) count <= count + 1; // one per tide
    end
endmodule
"""), ("gauge_pkg.sv", """// Gauge types.
package gauge_pkg;
  typedef logic [7:0] level_t;

  function automatic level_t clamp(input level_t v);
    return (v > 200) ? 200 : v;
  endfunction
endpackage

class gauge_model;
  int level;
endclass
""")],
    "vhdl": [("tide_counter.vhdl", """-- Tide pulse counter for the Saltmere gauge.
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity tide_counter is
  port (clk, pulse : in std_logic; count : out unsigned(7 downto 0));
end entity tide_counter;

architecture rtl of tide_counter is
  signal c : unsigned(7 downto 0) := (others => '0');
begin
  counter : process (clk)
  begin
    if rising_edge(clk) and pulse = '1' then
      c <= c + 1;
    end if;
  end process;
  count <= c;
end architecture rtl;
""")],
    "opencl": [("tides.cl", """// Tide model kernel for Saltmere Harbour.
#include "gauge.h"

/* One work item per gauge. */
__kernel void high_water(__global const float *base, __global float *out)
{
    int i = get_global_id(0);
    out[i] = base[i] + 1.5f * sin(M_PI_F / 6.0f);
}
""")],
    "glsl": [("tide.comp", """#version 450
// Tide model on the GPU for Saltmere Harbour.
#extension GL_GOOGLE_include_directive : enable

layout(local_size_x = 8, local_size_y = 8, local_size_z = 1) in;

layout(std430, binding = 0) buffer Levels { float level[]; };
layout(push_constant) uniform Params { float amplitude; };

float high_water(float base)
{
    return base + amplitude * sin(3.14159 / 6.0);
}

void main()
{
    uint i = gl_GlobalInvocationID.x;
    level[i] = high_water(level[i]);
}
"""), ("water.frag", """#version 450
// Water surface shading.
layout(location = 0) in vec2 uv;
layout(location = 0) out vec4 colour;

layout(binding = 1) uniform sampler2D ripples;

void main()
{
    colour = vec4(0.1, 0.3, 0.6, 1.0) * texture(ripples, uv);
}
""")],
    "hlsl": [("water.hlsl", """// Water surface shading for the harbour scene.
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
""")],
    "wgsl": [("tides.wgsl", """// Tide model for the harbour map.
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
""")],
    "metal": [("tides.metal", """// Tide model for the harbour map.
#include <metal_stdlib>
using namespace metal;

struct Gauge {
    float level;
};

kernel void high_water(device Gauge *gauges [[buffer(0)]], uint id [[thread_position_in_grid]])
{
    gauges[id].level += 1.5 * sin(M_PI_F / 6.0);
}
""")],
    "apex": [("BerthService.cls", """/**
 * Berth bookings for Saltmere Harbour.
 */
public with sharing class BerthService {
    // Berths in the inner basin.
    private static final Integer BERTHS = 12;

    public static Integer freeBerths(Integer booked) {
        return BERTHS - booked;
    }
}
"""), ("BookingTrigger.trigger", """// Keep berth counts current.
trigger BookingTrigger on Booking__c (after insert) {
    System.debug(BerthService.freeBerths(Trigger.new.size()));
}
""")],
    "abap": [("zharbour_berths.abap", """*&---------------------------------------------------------------------*
*& Report ZHARBOUR_BERTHS: berth fees for Saltmere Harbour
*&---------------------------------------------------------------------*
REPORT zharbour_berths.

INCLUDE zharbour_fees.

CLASS lcl_berth DEFINITION.
  PUBLIC SECTION.
    METHODS fee IMPORTING iv_length TYPE i RETURNING VALUE(rv_fee) TYPE i.
ENDCLASS.

CLASS lcl_berth IMPLEMENTATION.
  METHOD fee.
    rv_fee = iv_length * 8. " eight per metre
  ENDMETHOD.
ENDCLASS.

START-OF-SELECTION.
  WRITE / NEW lcl_berth( )->fee( 12 ).
""")],
    "smalltalk": [("Harbour.st", """"Berth allocation for Saltmere Harbour."
Object subclass: #Harbour
    instanceVariableNames: 'berths'
    classVariableNames: ''
    package: 'Saltmere-Harbour'!

!Harbour methodsFor: 'accessing'!
berths
    "Number of berths in the inner basin."
    ^ berths ifNil: [12]
! !
""")],
    "raku": [("Tides.rakumod", """# Tide model for Saltmere Harbour.
use v6.d;
use JSON::Fast;

unit module Tides;

class Gauge is export {
    has Str $.name;
    has Num $.level;
}

sub high-water(Gauge $g --> Num) is export {
    $g.level + 1.5e0 * sin(pi / 6)
}
""")],
    "starlark": [("BUILD.bazel", """# Build rules for the harbour tools.
load("@rules_python//python:defs.bzl", "py_binary", "py_library")

py_library(
    name = "tides",
    srcs = ["tides.py"],
)

py_binary(
    name = "report",
    srcs = ["report.py"],
    deps = [":tides"],
)
"""), ("defs.bzl", """\"\"\"Macros for harbour targets.\"\"\"

load("@bazel_skylib//lib:paths.bzl", "paths")

def harbour_test(name, srcs):
    native.py_test(name = name, srcs = srcs)
""")],
    "meson": [("meson.build", """# Build file for the harbour gauge daemon.
project('saltmere-gauge', 'c', version : '1.4.0', license : 'CC0-1.0')

glib = dependency('glib-2.0')
m = dependency('m')

subdir('docs')

exe = executable('gauged', 'gauged.c', dependencies : [glib, m])
lib = static_library('tides', 'tides.c')
test('tides', executable('test-tides', 'test.c', link_with : lib))
""")],
    "ninja": [("build.ninja", """# Generated for the harbour gauge daemon.
ninja_required_version = 1.5
cflags = -O2 -Wall

rule cc
  command = cc $cflags -c $in -o $out
  description = CC $out

rule link
  command = cc $in -o $out

build tides.o: cc tides.c
build gauged.o: cc gauged.c
build gauged: link gauged.o tides.o

default gauged
""")],
    "autohotkey": [("harbour.ahk", """; Hotkeys for the harbour logbook.
#Requires AutoHotkey v2.0
#Include lib\\Tides.ahk

/*
  Ctrl+Alt+T types the next high water.
*/
^!t::Send(NextHighWater())

NextHighWater() {
    return "14:20"
}
""")],
    "autoit": [("harbour.au3", """; Harbour logbook helper.
#include <MsgBoxConstants.au3>
#include "Tides.au3"

#cs
  Shows the next high water.
#ce
Func NextHighWater()
    Return "14:20"
EndFunc

MsgBox($MB_OK, "Saltmere", NextHighWater())
""")],
    "gleam": [("tides.gleam", """//// Tide model for Saltmere Harbour.

import gleam/float
import gleam/io

pub type Gauge {
  Gauge(name: String, level: Float)
}

const amplitude = 1.5

/// High water from a gauge's base level.
pub fn high_water(g: Gauge) -> Float {
  g.level +. amplitude
}

pub fn main() {
  io.println(float.to_string(high_water(Gauge("north", 2.0))))
}
""")],
    "roc": [("Tides.roc", """# Tide model for Saltmere Harbour.
module [high_water]

import Num

high_water : F64 -> F64
high_water = \\base ->
    # simple harmonic model
    base + 1.5
""")],
    "unison": [("tides.u", """-- Tide model for Saltmere Harbour.
use base

unique type Gauge = Gauge Text Float

highWater : Gauge -> Float
highWater = cases Gauge _ level -> level + 1.5
""")],
    "mojo": [("tides.mojo", """# Tide model for Saltmere Harbour.
from math import sin, pi

@value
struct Gauge:
    var name: String
    var level: Float64

fn high_water(g: Gauge) -> Float64:
    \"\"\"High water from the base level.\"\"\"
    return g.level + 1.5 * sin(pi / 6)

def main():
    print(high_water(Gauge("north", 2.0)))
""")],
    "qsharp": [("Tides.qs", """// Quantum coin for picking a berth (a teaching example).
namespace Saltmere.Tides {
    open Microsoft.Quantum.Measurement;

    /// Returns a random berth side.
    operation PickSide() : Result {
        use q = Qubit();
        H(q);
        return MResetZ(q);
    }

    function Berths() : Int {
        return 12;
    }
}
""")],
    "openqasm": [("coin.qasm", """// Quantum coin for the harbour lottery.
OPENQASM 3.0;
include "stdgates.inc";

gate flip q { h q; }

qubit[1] q;
bit[1] c;

flip q[0];
c[0] = measure q[0];
""")],
    "arduino": [("TideGauge.ino", """// Tide gauge float sensor for Saltmere Harbour.
#include <Wire.h>

#define SENSOR_PIN A0

int lastLevel = 0;

void setup() {
  Serial.begin(9600);
}

void loop() {
  lastLevel = analogRead(SENSOR_PIN); // raw level
  Serial.println(lastLevel);
  delay(1000);
}
""")],
    "llvm_ir": [("tides.ll", """; Tide model, compiled for the harbour gauge.
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
""")],
    "wat": [("tides.wat", """;; Tide model for the harbour web map.
(module $tides
  (import "env" "sin" (func $sin (param f64) (result f64)))
  (memory $mem 1)
  (global $amplitude f64 (f64.const 1.5))
  (; high water from a base level ;)
  (func $high_water (export "high_water") (param $base f64) (result f64)
    local.get $base
    global.get $amplitude
    f64.add))
""")],
    "antlr": [("Tide.g4", """// Grammar for tide table lines: "14:20 HW 3.4".
grammar Tide;

table : line+ EOF ;

line
    : TIME KIND LEVEL NEWLINE
    ;

TIME    : DIGIT DIGIT ':' DIGIT DIGIT ;
KIND    : 'HW' | 'LW' ;
LEVEL   : DIGIT+ '.' DIGIT+ ;
NEWLINE : '\\r'? '\\n' ;
WS      : [ \\t]+ -> skip ;
fragment DIGIT : [0-9] ;
""")],
    "peg": [("tide.peg", """# Tide table lines: "14:20 HW 3.4".
Table <- Line+ !.
Line  <- Time ' ' Kind ' ' Level '\\n'
Time  <- [0-9] [0-9] ':' [0-9] [0-9]
Kind  <- 'HW' / 'LW'
Level <- [0-9]+ '.' [0-9]+
""")],
    "yacc": [("tide.y", """/* Tide table parser for Saltmere Harbour. */
%{
#include <stdio.h>
%}

%token TIME KIND LEVEL NEWLINE
%start table

%%

table : line
      | table line
      ;

line  : TIME KIND LEVEL NEWLINE { printf("entry\\n"); }
      ;

%%
""")],
    "lex": [("tide.l", """/* Tide table scanner for Saltmere Harbour. */
%{
#include "tide.tab.h"
%}
%option noyywrap
%x COMMENT

%%
[0-9][0-9]:[0-9][0-9]  { return TIME; }
"HW"|"LW"              { return KIND; }
[0-9]+\\.[0-9]+         { return LEVEL; }
\\n                     { return NEWLINE; }
%%
""")],
    "puppet": [("harbour.pp", """# Gauge daemon for the Saltmere Harbour hosts.
class harbour::gauge (
  String $station = 'north',
) {
  include harbour::common

  package { 'saltmere-gauge':
    ensure => installed,
  }

  service { 'gauged':
    ensure  => running,
    require => Package['saltmere-gauge'],
  }
}

node 'gauge01.harbour.test' {
  include harbour::gauge
}
""")],
    "plsql": [("berths.pkb", """-- Berth fees for Saltmere Harbour.
CREATE OR REPLACE PACKAGE BODY berths AS
  /* Fee per metre of length. */
  FUNCTION fee(p_length IN NUMBER) RETURN NUMBER IS
  BEGIN
    RETURN p_length * 8;
  END fee;

  PROCEDURE book(p_vessel IN VARCHAR2) IS
  BEGIN
    INSERT INTO bookings (vessel) VALUES (p_vessel);
  END book;
END berths;
/
""")],
    "go_template": [("berths.tmpl", """{{/* Berth list page for Saltmere Harbour. */}}
{{define "berth"}}<li>{{.Number}}: {{.Vessel}}</li>{{end}}
<ul>
{{range .Berths}}{{template "berth" .}}{{end}}
</ul>
{{block "footer" .}}<p>Updated {{.Updated}}</p>{{end}}
""")],
    "handlebars": [("berths.hbs", """{{!-- Berth list for Saltmere Harbour --}}
{{> header title="Berths"}}
<ul>
  {{#each berths}}
    <li>{{number}}: {{vessel}}</li>
  {{/each}}
</ul>
{{#if updated}}<p>Updated {{updated}}</p>{{/if}}
""")],
    "pug": [("berths.pug", """//- Berth list for Saltmere Harbour.
extends layout.pug
include mixins/berth.pug

mixin berth(b)
  li= b.number + ': ' + b.vessel

block content
  h1 Berths
  ul
    each b in berths
      +berth(b)
""")],
    "vim_script": [("harbour.vim", """" Commands for the harbour logbook.
if exists('g:loaded_harbour')
  finish
endif
let g:loaded_harbour = 1

source ~/.vim/harbour-tides.vim

" Insert the next high water.
function! harbour#Tide() abort
  return '14:20'
endfunction

command! HarbourTide put =harbour#Tide()
nnoremap <leader>ht :HarbourTide<CR>

augroup harbour
  autocmd!
  autocmd BufRead *.log setlocal nowrap
augroup END
""")],
    "nushell": [("tides.nu", """# Tide report for Saltmere Harbour.
use std assert

# High water from a base level.
def high-water [base: float] {
    $base + 1.5
}

export def "harbour report" [] {
    open gauges.csv | each {|g| high-water $g.level }
}

alias hw = high-water
""")],
    "elvish": [("tides.elv", """# Tide report for Saltmere Harbour.
use str
use math

var amplitude = 1.5

fn high-water {|base|
  + $base $amplitude
}

echo (high-water 2.0)
""")],
    "rego": [("berths.rego", """# Berth booking policy for Saltmere Harbour.
package harbour.berths

import rego.v1

default allow := false

max_length := 30

allow if {
    input.vessel.length <= max_length
}

deny contains msg if {
    input.vessel.length > 60
    msg := "vessel too long for the harbour"
}
""")],
    "bicep": [("gauge.bicep", """// Storage for the harbour gauge readings.
targetScope = 'resourceGroup'

param location string = resourceGroup().location
var name = 'saltmeregauge'

resource store 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: name
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
}

module alerts './alerts.bicep' = {
  name: 'alerts'
}

output storeId string = store.id
""")],
    "lean": [("Tides.lean", """/-! Tide arithmetic for Saltmere Harbour. -/
import Mathlib.Data.Real.Basic

namespace Tides

/-- A gauge reading in centimetres. -/
structure Reading where
  level : Nat

def highWater (r : Reading) : Nat := r.level + 150

theorem highWater_gt (r : Reading) : r.level < highWater r := by
  unfold highWater; omega

end Tides
""")],
    "coq": [("Tides.v", """(* Tide arithmetic for Saltmere Harbour. *)
Require Import Arith.

Definition high_water (base : nat) : nat := base + 150.

Lemma high_water_gt : forall b, b < high_water b.
Proof.
  intros b. unfold high_water. lia.
Qed.
""")],
    "agda": [("Tides.agda", """-- Tide arithmetic for Saltmere Harbour.
module Tides where

open import Data.Nat using (ℕ; _+_)

record Reading : Set where
  field level : ℕ

highWater : Reading → ℕ
highWater r = Reading.level r + 150
""")],
    "idris": [("Tides.idr", """-- Tide arithmetic for Saltmere Harbour.
module Tides

import Data.Nat

||| A gauge reading in centimetres.
record Reading where
  constructor MkReading
  level : Nat

highWater : Reading -> Nat
highWater r = level r + 150
""")],
    "isabelle": [("Tides.thy", """(* Tide arithmetic for Saltmere Harbour. *)
theory Tides
  imports Main
begin

definition high_water :: "nat \\<Rightarrow> nat" where
  "high_water b = b + 150"

lemma high_water_gt: "b < high_water b"
  by (simp add: high_water_def)

end
""")],
    "tla": [("Berths.tla", """---------------------------- MODULE Berths ----------------------------
\\* Berth allocation for Saltmere Harbour.
EXTENDS Naturals, FiniteSets

CONSTANTS Vessels, MaxBerths
VARIABLES moored

TypeOK == moored \\subseteq Vessels
Init == moored = {}
Arrive(v) == /\\ Cardinality(moored) < MaxBerths
             /\\ moored' = moored \\cup {v}
Next == \\E v \\in Vessels : Arrive(v)

THEOREM Safety == TypeOK
=============================================================================
""")],
    "alloy": [("berths.als", """-- Berth allocation for Saltmere Harbour.
module harbour/berths
open util/ordering[Time]

sig Time {}
abstract sig Berth {}
one sig Inner, Outer extends Berth {}
sig Vessel { berth: Berth one -> Time }

fact oneVesselPerBerth { all t: Time | all b: Berth | lone berth.t.b }
pred moored[v: Vessel, t: Time] { some v.berth.t }
assert noClash { all t: Time | all b: Berth | lone berth.t.b }
check noClash for 4
""")],
    "ballerina": [("berths.bal", """// Berth service for Saltmere Harbour.
import ballerina/http;

type Berth record {|
    int number;
    string vessel;
|};

service /berths on new http:Listener(9090) {
    resource function get count() returns int {
        return 12;
    }
}

public function main() {
    io:println("ready");
}
""")],
    "pony": [("tides.pony", """// Tide model for Saltmere Harbour.
use "math"

actor Main
  new create(env: Env) =>
    env.out.print(Tides.high_water(2.0).string())

primitive Tides
  fun high_water(base: F64): F64 =>
    base + 1.5
""")],
    "janet": [("tides.janet", """# Tide model for Saltmere Harbour.
(import ./gauges)

(def amplitude 1.5)

(defn high-water
  "High water from a base level."
  [base]
  (+ base amplitude))

(defmacro report [x] ~(print ,x))

(report (high-water 2.0))
""")],
    "fennel": [("tides.fnl", """;; Tide model for Saltmere Harbour.
(local gauges (require :gauges))

(local amplitude 1.5)

(fn high-water [base]
  "High water from a base level."
  (+ base amplitude))

(print (high-water 2.0))
""")],
    "hy": [("tides.hy", """;; Tide model for Saltmere Harbour.
(import math)

(defclass Gauge []
  (defn __init__ [self level] (setv self.level level)))

(defn high-water [g]
  "High water from a gauge."
  (+ g.level (* 1.5 (math.sin (/ math.pi 6)))))

(print (high-water (Gauge 2.0)))
""")],
    "forth": [("tides.fth", """\\ Tide model for Saltmere Harbour (levels in cm).
150 constant amplitude
variable base-level

: high-water ( base -- hw )  amplitude + ;
: report ( -- )  base-level @ high-water . ;

200 base-level !
report
""")],
    "apl": [("Tides.apl", """⍝ Tide model for Saltmere Harbour (levels in cm).
:Namespace Tides
    amplitude←150
    HighWater←{⍵+amplitude}
    ⍝ Mean of a day's readings
    Mean←{(+/⍵)÷≢⍵}
:EndNamespace
""")],
    "j_lang": [("tides.ijs", """NB. Tide model for Saltmere Harbour (levels in cm).
require 'stats/base'
coclass 'tides'

amplitude =: 150
highwater =: 3 : 'y + amplitude'
mean =: +/ % #
""")],
    "gdscript": [("gauge.gd", """# Tide gauge node for the harbour scene.
class_name TideGauge
extends Node2D

signal level_changed(level: float)

const Ripple = preload("res://ripple.gd")

@export var amplitude: float = 1.5
var level := 0.0

func _process(delta: float) -> void:
	level = amplitude * sin(Time.get_ticks_msec() / 1000.0)
	level_changed.emit(level)
""")],
    "shaderlab": [("Water.shader", """// Water surface for the harbour scene.
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
""")],
    "plc_st": [("TidePump.st", """(* Bilge pump control for the harbour pontoon. *)
FUNCTION_BLOCK FB_TidePump
VAR_INPUT
    Level : REAL; // metres
END_VAR
VAR_OUTPUT
    PumpOn : BOOL;
END_VAR
    PumpOn := Level > 3.5;
END_FUNCTION_BLOCK

PROGRAM MAIN
VAR
    pump : FB_TidePump;
END_VAR
    pump(Level := 2.0);
END_PROGRAM
""")],
    "max_patch": [("tide.maxpat", """{
	"patcher" : {
		"fileversion" : 1,
		"appversion" : { "major" : 8, "minor" : 6, "revision" : 0 },
		"boxes" : [
			{ "box" : { "id" : "obj-1", "maxclass" : "newobj", "text" : "cycle~ 0.1" } },
			{ "box" : { "id" : "obj-2", "maxclass" : "ezdac~" } },
			{ "box" : { "id" : "obj-3", "maxclass" : "comment", "text" : "tide drone" } }
		],
		"lines" : [
			{ "patchline" : { "source" : [ "obj-1", 0 ], "destination" : [ "obj-2", 0 ] } }
		]
	}
}
""")],
    "pure_data": [("tide.pd", """#N canvas 0 50 450 300 12;
#X obj 30 30 osc~ 0.1;
#X obj 30 80 *~ 0.2;
#X obj 30 130 dac~;
#X msg 150 30 \\; pd dsp 1;
#X text 150 80 tide drone;
#N canvas 0 0 300 200 swell 0;
#X obj 20 20 inlet~;
#X restore 150 130 pd swell;
#X connect 0 0 1 0;
#X connect 1 0 2 0;
""")],
    "yara": [("harbour.yar", """// Finds Saltmere Harbour tide tables in a document store.
import "pe"

rule saltmere_tide_table : harbour docs
{
    meta:
        description = "Tide table exported by the harbour office"
    strings:
        $title = "Saltmere Harbour tide table"
    condition:
        $title
}

private rule harbour_header
{
    strings:
        $h = "SALTMERE"
    condition:
        $h at 0
}
""")],
    "smithy": [("berths.smithy", """$version: "2"

namespace harbour.berths

use aws.protocols#restJson1

/// Berth bookings for Saltmere Harbour.
@restJson1
service BerthService {
    version: "2026-01-01"
    operations: [GetBerth]
}

@readonly
operation GetBerth {
    input := { @required number: Integer }
    output := { vessel: String }
}

structure Berth {
    number: Integer
}
""")],
    "avro_idl": [("berths.avdl", """// Berth booking events for Saltmere Harbour.
@namespace("harbour.berths")
protocol Berths {
    import idl "common.avdl";

    enum Basin { INNER, OUTER }

    record Booking {
        string vessel;
        int berth;
        Basin basin = "INNER";
    }

    fixed Checksum(16);
}
""")],
    "applescript": [("harbour.applescript", """-- Shows the next high water at Saltmere Harbour.
use AppleScript version "2.4"
use scripting additions

(* The tide table lives in a text file. *)
on nextHighWater()
	return "14:20"
end nextHighWater

on run
	display notification nextHighWater() with title "Saltmere"
end run
""")],
    "groovy": [("harbour.groovy", """// Berth report for Saltmere Harbour.
package saltmere

import groovy.json.JsonOutput

class Berth {
    int number
    String vessel
}

def report(List<Berth> berths) {
    println JsonOutput.toJson(berths)
}

report([new Berth(number: 3, vessel: 'Tern')])
""")],
}
