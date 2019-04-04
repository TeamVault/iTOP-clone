grammar esl;
esl         :   imports definitions main? ;

imports     :   ((py_import | esl_import) ';')* ;
py_import   :   'IMPORT' GADGET_ID '(' types ')' 'RETURNS' (TYPE | 'NONE') 'FROM' STRING;
esl_import  :   'IMPORT' STRING ;

definitions :   definition* ;
definition  :   'DEF' GADGET_ID '(' arg_ids? ')' 'RETURNS' (TYPE | 'NONE') '{' statements '}' ;

arg_ids     :   ARG_ID (',' ARG_ID)* ;

main	    :   GADGET_ID '{' statements '}' ;
statements	:   (((statement ';')| (assert_stmt ';') | (jmp_stmt ';') | (if_stmt ';') | (label_stmt ':') ))* ;
statement	:   gadget | assignment | reg_assign ;
gadget	    :   GADGET_ID '(' arguments? ')' ;
arguments	:   argument (',' argument)* ;
argument	:   '&'? ARG_ID | REG_ID;
assignment  :   (TYPE ARG_ID) '=' ( STRING | INT ) ;
reg_assign  :   TYPE REG_ID '=' GADGET_ID '(' arguments? ')' ;

assert_stmt :   'ASSERT' REG_ID CMP_OP (INT | REG_ID | ARG_ID | STRING) ;
jmp_stmt    :   'GOTO' LABEL_ID ;
if_stmt     :   'IF' REG_ID CMP_OP INT 'GOTO' LABEL_ID ;
label_stmt  :   LABEL_ID ;

CMP_OP      :   '<' | '>' | '==' ;

types       :   (TYPE (',' TYPE)*)? ;

REG_ID      :   '_r0' | '_r1' | '_r2' | '_r3' | '_r4' | '_r5' | '_r6' | '_r7' ;

TYPE        :   'string' | 'int' | 'reg' ;
GADGET_ID   :   [A-Z_0-9]+ ;
ARG_ID	    :   [a-z]+ ;
STRING      :   '"' ~('\r' | '\n' | '"')* '"' ;
INT         :   [0-9]+ | '0x'[0-9a-fA-F]+ ;
LABEL_ID    :   '_'[a-z]+ ;

WS		    :   [ \t\r\n]+ -> skip ;
LINE_COMMENT: '//' ~[\r\n]* -> skip ;