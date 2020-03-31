rule WebShell_BackDoor_Unlimit_Hytop_Devpack_2005Red_A_1285 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2005Red.asp"
    family = "Hytop"
    hacker = "None"
    hash = "d8ccda2214b3f6eabd4502a050eb8fe8"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hytop.Devpack.2005Red.A"
    threattype = "BackDoor"
  strings:
    $s0 = "scrollbar-darkshadow-color:#FF9DBB;"
    $s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
    $s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
  condition:
    all of them
}