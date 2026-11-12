// Tide pulse counter for the Saltmere gauge.
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
