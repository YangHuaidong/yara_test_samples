rule WebShell_BackDoor_Unlimit_Sig_2005Gray_A_1431 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2005Gray.asp"
    family = "Sig"
    hacker = "None"
    hash = "75dbe3d3b70a5678225d3e2d78b604cc"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Sig.2005Gray.A"
    threattype = "BackDoor"
  strings:
    $s0 = "SCROLLBAR-FACE-COLOR: #e8e7e7;"
    $s4 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
    $s8 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
    $s9 = "SCROLLBAR-3DLIGHT-COLOR: #cccccc;"
  condition:
    all of them
}