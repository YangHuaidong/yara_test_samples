rule WebShell_BackDoor_Unlimit_Casus15_Php_Php_A_1205 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Casus15.php.php.txt"
    family = "Casus15"
    hacker = "None"
    hash = "5e2ede2d1c4fa1fcc3cbfe0c005d7b13"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Casus15.Php.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na"
    $s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'"
    $s3 = "value='Calistirmak istediginiz "
  condition:
    1 of them
}