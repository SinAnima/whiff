function h = tide_height(t, mean_level, amplitude)
% TIDE_HEIGHT  Height of the tide at Saltmere at time t (hours).
%   h = tide_height(t, 2.4, 1.6)
%{
  The M2 constituent only: period 12.42 hours.
%}
import saltmere.constants.*
if nargin < 2
    mean_level = 2.4;
end
h = mean_level + amplitude .* cos(2 * pi * t / 12.42);
end

function plot_day()
% Plot a day of tides.
t = 0:0.25:24;
plot(t, tide_height(t, 2.4, 1.6));
end
