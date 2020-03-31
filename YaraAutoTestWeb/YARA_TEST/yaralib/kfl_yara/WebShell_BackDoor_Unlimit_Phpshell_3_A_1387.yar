rule WebShell_BackDoor_Unlimit_Phpshell_3_A_1387 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file phpshell.php"
    family = "Phpshell"
    hacker = "None"
    hash = "e8693a2d4a2ffea4df03bb678df3dc6d"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Phpshell.3.A"
    threattype = "BackDoor"
  strings:
    $s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
    $s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";"
  condition:
    all of them
}