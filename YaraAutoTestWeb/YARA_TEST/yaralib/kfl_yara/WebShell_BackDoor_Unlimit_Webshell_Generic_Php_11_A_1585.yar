rule WebShell_BackDoor_Unlimit_Webshell_Generic_Php_11_A_1585 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files rootshell.php, Rootshell.v.1.0.php, s72 Shell v1.1 Coding.php, s72_Shell_v1.1_Coding.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "31a82cbee8dffaf8eb7b73841f3f3e8e9b3e78cf"
    hash1 = "838c7191cb10d5bb0fc7460b4ad0c18c326764c6"
    hash2 = "8dfcd919d8ddc89335307a7b2d5d467b1fd67351"
    hash3 = "80aba3348434c66ac471daab949871ab16c50042"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Generic.Php.11.A"
    threattype = "BackDoor"
  strings:
    $s5 = "$filename = $backupstring.\"$filename\";" fullword
    $s6 = "while ($file = readdir($folder)) {" fullword
    $s7 = "if($file != \".\" && $file != \"..\")" fullword
    $s9 = "$backupstring = \"copy_of_\";" fullword
    $s10 = "if( file_exists($file_name))" fullword
    $s13 = "global $file_name, $filename;" fullword
    $s16 = "copy($file,\"$filename\");" fullword
    $s18 = "<td width=\"49%\" height=\"142\">" fullword
  condition:
    all of them
}