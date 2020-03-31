rule WebShell_BackDoor_Unlimit_C99Shell_A_1204 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file c99shell.php"
    family = "C99Shell"
    hacker = "None"
    hash = "90b86a9c63e2cd346fe07cea23fbfc56"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.C99Shell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&"
  condition:
    all of them
}