rule WebShell_BackDoor_Unlimit_Hytop_Apppack_2005_A_1282 {
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
    threatname = "WebShell[BackDoor]/Unlimit.Hytop.Apppack.2005.A"
    threattype = "BackDoor"
  strings:
    $s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"
  condition:
    all of them
}