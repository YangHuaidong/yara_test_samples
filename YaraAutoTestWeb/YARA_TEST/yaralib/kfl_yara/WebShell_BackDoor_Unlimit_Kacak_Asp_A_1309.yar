rule WebShell_BackDoor_Unlimit_Kacak_Asp_A_1309 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file kacak.asp.txt"
    family = "Kacak"
    hacker = "None"
    hash = "907d95d46785db21331a0324972dda8c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Kacak.Asp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Kacak FSO 1.0"
    $s1 = "if request.querystring(\"TGH\") = \"1\" then"
    $s3 = "<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style="
    $s4 = "mailto:BuqX@hotmail.com"
  condition:
    1 of them
}