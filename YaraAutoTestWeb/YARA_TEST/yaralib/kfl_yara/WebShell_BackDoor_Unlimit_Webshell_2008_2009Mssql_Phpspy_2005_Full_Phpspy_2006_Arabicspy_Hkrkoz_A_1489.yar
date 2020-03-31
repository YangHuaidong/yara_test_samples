rule WebShell_BackDoor_Unlimit_Webshell_2008_2009Mssql_Phpspy_2005_Full_Phpspy_2006_Arabicspy_Hkrkoz_A_1489 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
    hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
    hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
    hash3 = "40a1f840111996ff7200d18968e42cfe"
    hash4 = "e0202adff532b28ef1ba206cf95962f2"
    hash5 = "802f5cae46d394b297482fd0c27cb2fc"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.2008.2009Mssql.Phpspy.2005.Full.Phpspy.2006.Arabicspy.Hkrkoz.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$this -> addFile($content, $filename);" fullword
    $s3 = "function addFile($data, $name, $time = 0) {" fullword
    $s8 = "function unix2DosTime($unixtime = 0) {" fullword
    $s9 = "foreach($filelist as $filename){" fullword
  condition:
    all of them
}