rule WebShell_BackDoor_Unlimit_H4Ntu_Shell__Powered_By_Tsoi__A_1272 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file h4ntu shell [powered by tsoi].txt"
    family = "H4Ntu"
    hacker = "None"
    hash = "06ed0b2398f8096f1bebf092d0526137"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.H4Ntu.Shell..Powered.By.Tsoi..A"
    threattype = "BackDoor"
  strings:
    $s0 = "h4ntu shell"
    $s1 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");"
  condition:
    1 of them
}