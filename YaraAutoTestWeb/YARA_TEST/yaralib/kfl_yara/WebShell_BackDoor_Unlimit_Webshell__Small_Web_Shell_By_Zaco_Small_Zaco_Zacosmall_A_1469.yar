rule WebShell_BackDoor_Unlimit_Webshell__Small_Web_Shell_By_Zaco_Small_Zaco_Zacosmall_A_1469 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files Small Web Shell by ZaCo.php, small.php, zaco.php, zacosmall.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "b148ead15d34a55771894424ace2a92983351dda"
    hash1 = "e4ba288f6d46dc77b403adf7d411a280601c635b"
    hash2 = "e5713d6d231c844011e9a74175a77e8eb835c856"
    hash3 = "1b836517164c18caf2c92ee2a06c645e26936a0c"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell..Small.Web.Shell.By.Zaco.Small.Zaco.Zacosmall.A"
    threattype = "BackDoor"
  strings:
    $s2 = "if(!$result2)$dump_file.='#error table '.$rows[0];" fullword
    $s4 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" fullword
    $s6 = "header('Content-Length: '.strlen($dump_file).\"\\n\");" fullword
    $s20 = "echo('Dump for '.$db_dump.' now in '.$to_file);" fullword
  condition:
    2 of them
}