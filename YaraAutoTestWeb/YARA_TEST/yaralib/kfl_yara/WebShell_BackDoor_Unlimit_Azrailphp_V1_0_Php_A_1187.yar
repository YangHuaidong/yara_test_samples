rule WebShell_BackDoor_Unlimit_Azrailphp_V1_0_Php_A_1187 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file aZRaiLPhp v1.0.php.txt"
    family = "Azrailphp"
    hacker = "None"
    hash = "26b2d3943395682e36da06ed493a3715"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Azrailphp.V1.0.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "azrailphp"
    $s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>"
    $s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>"
  condition:
    2 of them
}