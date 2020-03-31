rule WebShell_BackDoor_Unlimit_Simple_Cmd_Html_A_1435 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file simple_cmd.html.txt"
    family = "Simple"
    hacker = "None"
    hash = "c6381412df74dbf3bcd5a2b31522b544"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Simple.Cmd.Html.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<title>G-Security Webshell</title>" fullword
    $s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
    $s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
    $s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
  condition:
    all of them
}