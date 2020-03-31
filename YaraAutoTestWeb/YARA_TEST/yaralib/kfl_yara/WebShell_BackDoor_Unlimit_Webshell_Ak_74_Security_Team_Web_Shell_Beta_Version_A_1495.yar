rule WebShell_BackDoor_Unlimit_Webshell_Ak_74_Security_Team_Web_Shell_Beta_Version_A_1495 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file AK-74 Security Team Web Shell Beta Version.php"
    family = "Webshell"
    hacker = "None"
    hash = "c90b0ba575f432ecc08f8f292f3013b5532fe2c4"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Ak.74.Security.Team.Web.Shell.Beta.Version.A"
    threattype = "BackDoor"
  strings:
    $s8 = "- AK-74 Security Team Web Site: www.ak74-team.net" fullword
    $s9 = "<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'."
    $s10 = "<b><font color=#83000>Execute system commands!</font></b>" fullword
  condition:
    1 of them
}