rule WebShell_BackDoor_Unlimit_Nshell__1__Php_Php_A_1360 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Nshell (1).php.php.txt"
    family = "Nshell"
    hacker = "None"
    hash = "973fc89694097a41e684b43a21b1b099"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Nshell..1..Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($"
    $s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";" fullword
  condition:
    1 of them
}