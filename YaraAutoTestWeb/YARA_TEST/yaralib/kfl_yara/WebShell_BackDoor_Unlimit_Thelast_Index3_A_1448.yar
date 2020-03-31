rule WebShell_BackDoor_Unlimit_Thelast_Index3_A_1448 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file index3.php"
    family = "Thelast"
    hacker = "None"
    hash = "cceff6dc247aaa25512bad22120a14b4"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Thelast.Index3.A"
    threattype = "BackDoor"
  strings:
    $s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r"
  condition:
    all of them
}