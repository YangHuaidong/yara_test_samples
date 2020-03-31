rule WebShell_BackDoor_Unlimit_Hytop_Devpack_2005_A_1284 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2005.asp"
    family = "Hytop"
    hacker = "None"
    hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hytop.Devpack.2005.A"
    threattype = "BackDoor"
  strings:
    $s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")"
    $s8 = "scrollbar-darkshadow-color:#9C9CD3;"
    $s9 = "scrollbar-face-color:#E4E4F3;"
  condition:
    all of them
}