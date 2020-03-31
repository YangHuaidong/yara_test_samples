rule WebShell_BackDoor_Unlimit_Webshell_Php_A_A_1653 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file a.php"
    family = "Webshell"
    hacker = "None"
    hash = "e3b461f7464d81f5022419d87315a90d"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Php.A.A"
    threattype = "BackDoor"
  strings:
    $s1 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\""
    $s2 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>"
    $s4 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> " fullword
  condition:
    2 of them
}