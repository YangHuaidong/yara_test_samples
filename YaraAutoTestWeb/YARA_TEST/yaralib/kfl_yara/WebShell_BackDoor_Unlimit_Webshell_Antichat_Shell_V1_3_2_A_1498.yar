rule WebShell_BackDoor_Unlimit_Webshell_Antichat_Shell_V1_3_2_A_1498 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Antichat Shell v1.3.php"
    family = "Webshell"
    hacker = "None"
    hash = "40d0abceba125868be7f3f990f031521"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Antichat.Shell.V1.3.2.A"
    threattype = "BackDoor"
  strings:
    $s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m"
  condition:
    all of them
}