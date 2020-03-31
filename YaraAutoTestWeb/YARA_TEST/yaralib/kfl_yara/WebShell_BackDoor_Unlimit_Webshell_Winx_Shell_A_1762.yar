rule WebShell_BackDoor_Unlimit_Webshell_Winx_Shell_A_1762 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file WinX Shell.php"
    family = "Webshell"
    hacker = "None"
    hash = "a94d65c168344ad9fa406d219bdf60150c02010e"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Winx.Shell.A"
    threattype = "BackDoor"
  strings:
    $s4 = "// It's simple shell for all Win OS." fullword
    $s5 = "//------- [netstat -an] and [ipconfig] and [tasklist] ------------" fullword
    $s6 = "<html><head><title>-:[GreenwooD]:- WinX Shell</title></head>" fullword
    $s13 = "// Created by greenwood from n57" fullword
    $s20 = " if (is_uploaded_file($userfile)) {" fullword
  condition:
    3 of them
}