rule WebShell_BackDoor_Unlimit_Webshell_Sst_Sheller_A_1734 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Sst-Sheller.php"
    family = "Webshell"
    hacker = "None"
    hash = "d93c62a0a042252f7531d8632511ca56"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Sst.Sheller.A"
    threattype = "BackDoor"
  strings:
    $s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>"
    $s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)"
  condition:
    all of them
}