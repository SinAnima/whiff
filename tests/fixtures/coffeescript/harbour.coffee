# Berth allocation for Saltmere Harbour.
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
