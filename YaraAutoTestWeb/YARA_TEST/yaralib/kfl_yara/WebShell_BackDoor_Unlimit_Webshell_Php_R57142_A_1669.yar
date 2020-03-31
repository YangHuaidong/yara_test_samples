rule WebShell_BackDoor_Unlimit_Webshell_Php_R57142_A_1669 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file r57142.php"
    family = "Webshell"
    hacker = "None"
    hash = "0911b6e6b8f4bcb05599b2885a7fe8a8"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.R57142.A"
    threattype = "BackDoor"
  strings:
    $s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword
  condition:
    all of them
}