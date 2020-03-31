rule WebShell_BackDoor_Unlimit_Ebayid_Index3_A_1233 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file index3.php"
    family = "Ebayid"
    hacker = "None"
    hash = "0412b1e37f41ea0d002e4ed11608905f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Ebayid.Index3.A"
    threattype = "BackDoor"
  strings:
    $s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You"
  condition:
    all of them
}