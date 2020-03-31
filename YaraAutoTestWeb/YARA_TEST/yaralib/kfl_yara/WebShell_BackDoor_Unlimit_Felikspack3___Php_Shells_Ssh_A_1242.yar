rule WebShell_BackDoor_Unlimit_Felikspack3___Php_Shells_Ssh_A_1242 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file ssh.php"
    family = "Felikspack3"
    hacker = "None"
    hash = "1aa5307790d72941589079989b4f900e"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Felikspack3...Php.Shells.Ssh.A"
    threattype = "BackDoor"
  strings:
    $s0 = "eval(gzinflate(str_rot13(base64_decode('"
  condition:
    all of them
}