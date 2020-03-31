rule WebShell_BackDoor_Unlimit_Thelast_Orice2_A_1449 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file orice2.php"
    family = "Thelast"
    hacker = "None"
    hash = "aa63ffb27bde8d03d00dda04421237ae"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Thelast.Orice2.A"
    threattype = "BackDoor"
  strings:
    $s0 = " $aa = $_GET['aa'];"
    $s1 = "echo $aa;"
  condition:
    all of them
}