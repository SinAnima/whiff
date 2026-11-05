# Harbour berth allocation.
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
