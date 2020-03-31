rule WebShell_BackDoor_Unlimit_Webshell_Php_Webshells_Aspydrv_A_1677 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file aspydrv.php"
    family = "Webshell"
    hacker = "None"
    hash = "3d8996b625025dc549d73cdb3e5fa678ab35d32a"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.Webshells.Aspydrv.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files"
    $s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
    $s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
    $s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
    $s20 = "' ---Copy Too Folder routine Start" fullword
  condition:
    3 of them
}