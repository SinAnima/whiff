// Grammar for tide table lines: "14:20 HW 3.4".
grammar Tide;

table : line+ EOF ;

line
    : TIME KIND LEVEL NEWLINE
    ;

TIME    : DIGIT DIGIT ':' DIGIT DIGIT ;
KIND    : 'HW' | 'LW' ;
LEVEL   : DIGIT+ '.' DIGIT+ ;
NEWLINE : '\r'? '\n' ;
WS      : [ \t]+ -> skip ;
fragment DIGIT : [0-9] ;
