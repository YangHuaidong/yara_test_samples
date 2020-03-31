rule WebShell_BackDoor_Unlimit_Efso_2_Asp_A_1236 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file EFSO_2.asp.txt"
    family = "Efso"
    hacker = "None"
    hash = "b5fde9682fd63415ae211d53c6bfaa4d"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Efso.2.Asp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Ejder was HERE"
    $s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~"
  condition:
    2 of them
}