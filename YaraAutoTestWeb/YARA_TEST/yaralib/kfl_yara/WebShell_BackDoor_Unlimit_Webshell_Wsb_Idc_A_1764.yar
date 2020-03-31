rule WebShell_BackDoor_Unlimit_Webshell_Wsb_Idc_A_1764 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file idc.php"
    family = "Webshell"
    hacker = "None"
    hash = "7c5b1b30196c51f1accbffb80296395f"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Wsb.Idc.A"
    threattype = "BackDoor"
  strings:
    $s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
    $s3 = "{eval($_GET['idc']);}" fullword
  condition:
    1 of them
}