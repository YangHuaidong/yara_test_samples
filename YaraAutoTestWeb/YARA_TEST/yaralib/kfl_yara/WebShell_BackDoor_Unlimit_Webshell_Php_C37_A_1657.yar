rule WebShell_BackDoor_Unlimit_Webshell_Php_C37_A_1657 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file c37.php"
    family = "Webshell"
    hacker = "None"
    hash = "d01144c04e7a46870a8dd823eb2fe5c8"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.C37.A"
    threattype = "BackDoor"
  strings:
    $s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),"
    $s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],"
  condition:
    all of them
}