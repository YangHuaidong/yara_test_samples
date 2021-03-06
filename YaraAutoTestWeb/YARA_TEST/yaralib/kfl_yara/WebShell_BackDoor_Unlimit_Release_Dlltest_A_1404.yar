rule WebShell_BackDoor_Unlimit_Release_Dlltest_A_1404 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file dllTest.dll"
    family = "Release"
    hacker = "None"
    hash = "76a59fc3242a2819307bb9d593bef2e0"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Release.Dlltest.A"
    threattype = "BackDoor"
  strings:
    $s0 = ";;;Y;`;d;h;l;p;t;x;|;"
    $s1 = "0 0&00060K0R0X0f0l0q0w0"
    $s2 = ": :$:(:,:0:4:8:D:`=d="
    $s3 = "4@5P5T5\\5T7\\7d7l7t7|7"
    $s4 = "1,121>1C1K1Q1X1^1e1k1s1y1"
    $s5 = "9 9$9(9,9P9X9\\9`9d9h9l9p9t9x9|9"
    $s6 = "0)0O0\\0a0o0\"1E1P1q1"
    $s7 = "<.<I<d<h<l<p<t<x<|<"
    $s8 = "3&31383>3F3Q3X3`3f3w3|3"
    $s9 = "8@;D;H;L;P;T;X;\\;a;9=W=z="
  condition:
    all of them
}