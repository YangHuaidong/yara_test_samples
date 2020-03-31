rule WebShell_BackDoor_Unlimit_Imhapftp_A_1295 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file iMHaPFtp.php"
    family = "Imhapftp"
    hacker = "None"
    hash = "12911b73bc6a5d313b494102abcf5c57"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Imhapftp.A"
    threattype = "BackDoor"
  strings:
    $s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"
  condition:
    all of them
}