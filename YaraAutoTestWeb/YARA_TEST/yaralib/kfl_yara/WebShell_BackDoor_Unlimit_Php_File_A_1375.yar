rule WebShell_BackDoor_Unlimit_Php_File_A_1375 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file file.php"
    family = "Php"
    hacker = "None"
    hash = "7421d33e8007c92c8642a36cba7351c7f95a4335"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Php.File.A"
    threattype = "BackDoor"
  strings:
    $s1 = "$allowedIPs =" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
    $s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii
  condition:
    filesize < 10KB and all of them
}