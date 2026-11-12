// Gauge types.
package gauge_pkg;
  typedef logic [7:0] level_t;

  function automatic level_t clamp(input level_t v);
    return (v > 200) ? 200 : v;
  endfunction
endpackage

class gauge_model;
  int level;
endclass
