rule WebShell_BackDoor_Unlimit_Sendmail_A_1418 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file sendmail.exe"
    family = "Sendmail"
    hacker = "None"
    hash = "75b86f4a21d8adefaf34b3a94629bd17"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Sendmail.A"
    threattype = "BackDoor"
  strings:
    $s3 = "_NextPyC808"
    $s6 = "Copyright (C) 2000, Diamond Computer Systems Pty. Ltd. (www.diamondcs.com.au)"
  condition:
    all of them
}