rule WebShell_BackDoor_Unlimit_Hytop_Devpack_Config_A_1286 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file config.asp"
    family = "Hytop"
    hacker = "None"
    hash = "b41d0e64e64a685178a3155195921d61"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hytop.Devpack.Config.A"
    threattype = "BackDoor"
  strings:
    $s0 = "const adminPassword=\""
    $s2 = "const userPassword=\""
    $s3 = "const mVersion="
  condition:
    all of them
}