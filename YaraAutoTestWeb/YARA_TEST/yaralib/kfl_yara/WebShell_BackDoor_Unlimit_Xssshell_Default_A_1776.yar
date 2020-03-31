rule WebShell_BackDoor_Unlimit_Xssshell_Default_A_1776 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file default.asp"
    family = "Xssshell"
    hacker = "None"
    hash = "d156782ae5e0b3724de3227b42fcaf2f"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Xssshell.Default.A"
    threattype = "BackDoor"
  strings:
    $s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"
  condition:
    all of them
}