/* Tide table scanner for Saltmere Harbour. */
%{
#include "tide.tab.h"
%}
%option noyywrap
%x COMMENT

%%
[0-9][0-9]:[0-9][0-9]  { return TIME; }
"HW"|"LW"              { return KIND; }
[0-9]+\.[0-9]+         { return LEVEL; }
\n                     { return NEWLINE; }
%%
