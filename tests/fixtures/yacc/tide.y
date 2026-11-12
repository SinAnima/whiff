/* Tide table parser for Saltmere Harbour. */
%{
#include <stdio.h>
%}

%token TIME KIND LEVEL NEWLINE
%start table

%%

table : line
      | table line
      ;

line  : TIME KIND LEVEL NEWLINE { printf("entry\n"); }
      ;

%%
