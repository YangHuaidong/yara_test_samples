rule WebShell_BackDoor_Unlimit_Phpinj_Php_Php_A_1385 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file pHpINJ.php.php.txt"
    family = "Phpinj"
    hacker = "None"
    hash = "d7a4b0df45d34888d5a09f745e85733f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Phpinj.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s1 = "News Remote PHP Shell Injection"
    $s3 = "Php Shell <br />" fullword
    $s4 = "<input type = \"text\" name = \"url\" value = \""
  condition:
    2 of them
}