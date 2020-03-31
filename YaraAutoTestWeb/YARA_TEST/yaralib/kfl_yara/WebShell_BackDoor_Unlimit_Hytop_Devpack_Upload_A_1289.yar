rule WebShell_BackDoor_Unlimit_Hytop_Devpack_Upload_A_1289 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file upload.asp"
    family = "Hytop"
    hacker = "None"
    hash = "b09852bda534627949f0259828c967de"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hytop.Devpack.Upload.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<!-- PageUpload Below -->"
  condition:
    all of them
}