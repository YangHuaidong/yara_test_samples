rule WebShell_BackDoor_Unlimit_Webshell_Ironshell_A_1599 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file ironshell.php"
    family = "Webshell"
    hacker = "None"
    hash = "d47b8ba98ea8061404defc6b3a30839c4444a262"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Ironshell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<title>'.getenv(\"HTTP_HOST\").' ~ Shell I</title>" fullword
    $s2 = "$link = mysql_connect($_POST['host'], $_POST['username'], $_POST"
    $s4 = "error_reporting(0); //If there is an error, we'll show it, k?" fullword
    $s8 = "print \"<form action=\\\"\".$me.\"?p=chmod&file=\".$content.\"&d"
    $s15 = "if(!is_numeric($_POST['timelimit']))" fullword
    $s16 = "if($_POST['chars'] == \"9999\")" fullword
    $s17 = "<option value=\\\"az\\\">a - zzzzz</option>" fullword
    $s18 = "print shell_exec($command);" fullword
  condition:
    3 of them
}