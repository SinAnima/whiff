-- Tide pulse counter for the Saltmere gauge.
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
