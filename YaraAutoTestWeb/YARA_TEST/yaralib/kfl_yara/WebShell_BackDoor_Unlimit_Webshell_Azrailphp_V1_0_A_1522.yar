rule WebShell_BackDoor_Unlimit_Webshell_Azrailphp_V1_0_A_1522 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file aZRaiLPhp v1.0.php"
    family = "Webshell"
    hacker = "None"
    hash = "a2c609d1a8c8ba3d706d1d70bef69e63f239782b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Azrailphp.V1.0.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED"
    $s4 = "$fileperm=base_convert($_POST['fileperm'],8,10);" fullword
    $s19 = "touch (\"$path/$dismi\") or die(\"Dosya Olu" fullword
    $s20 = "echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G" fullword
  condition:
    2 of them
}