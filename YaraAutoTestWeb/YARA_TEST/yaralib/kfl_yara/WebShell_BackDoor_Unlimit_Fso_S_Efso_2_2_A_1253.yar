rule WebShell_BackDoor_Unlimit_Fso_S_Efso_2_2_A_1253 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file EFSO_2.asp"
    family = "Fso"
    hacker = "None"
    hash = "a341270f9ebd01320a7490c12cb2e64c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Efso.2.2.A"
    threattype = "BackDoor"
  strings:
    $s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
    $s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
  condition:
    all of them
}