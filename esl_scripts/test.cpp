DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
    READ_INTO_R1(arg);
    EXECUTE(target, _r1);
}
//
//DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
//    READ_INTO_R2(arg);
//    EXECUTE(target, _r2);
//}
//
//DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
//    READ_INTO_R3(arg);
//    EXECUTE(target, _r3);
//}
//
//DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
//    READ_INTO_R4(arg);
//    EXECUTE(target, _r4);
//}
//
//DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
//    READ_INTO_R5(arg);
//    EXECUTE(target, _r5);
//}

DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
    EXECUTE(target, arg);
}

//DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
//    READ_INTO_R1(target);
//    EXECUTE(_r1, arg);
//}
//
//DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
//    READ_INTO_R2(target);
//    EXECUTE(_r2, arg);
//}
//
//DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
//    READ_INTO_R3(target);
//    EXECUTE(_r3, arg);
//}
//
//DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
//    READ_INTO_R4(target);
//    EXECUTE(_r4, arg);
//}
//
//DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
//    READ_INTO_R5(target);
//    EXECUTE(_r5, arg);
//}

DEF EXECUTE_ONE_ARG(target, arg) RETURNS NONE {
    READ_INTO_R1(target);
    READ_INTO_R2(arg);
    ASSERT _r1 == target;
    EXECUTE(target, arg);
}

DEF EXECUTE_THREE_ARGS(target, argone, argtwo, argthree) RETURNS NONE {
    EXECUTE(target, argone, argtwo, argthree);
}

DEF EXECUTE_THREE_ARGS(target, argone, argtwo, argthree) RETURNS NONE {
    READ_INTO_R1(argone);
    READ_INTO_R2(argthree);
    ASSERT _r1 == argone;
    EXECUTE(target, _r1, argtwo, _r2);
}

DEF EXECUTE_THREE_ARGS(target, argone, argtwo, argthree) RETURNS NONE {
    READ_INTO_R1(target);
    READ_INTO_R2(argone);
    ASSERT _r1 == target;
    READ_INTO_R3(argtwo);
    ASSERT _r1 == target;
    ASSERT _r2 == argone;
    READ_INTO_R4(argthree);
    ASSERT _r1 == target;
    ASSERT _r2 == argone;
    ASSERT _r3 == argtwo;
    EXECUTE(_r1, _r2, _r3, _r4);
}