rule WebShell_BackDoor_Unlimit_Safe0Ver_Shell__Safe_Mod_Bypass_By_Evilc0Der_Php_A_1415 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Safe0ver Shell -Safe Mod Bypass By Evilc0der.php.txt"
    family = "Safe0Ver"
    hacker = "None"
    hash = "6163b30600f1e80d2bb5afaa753490b6"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Safe0Ver.Shell..Safe.Mod.Bypass.By.Evilc0Der.Php.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Safe0ver" fullword
    $s1 = "Script Gecisi Tamamlayamadi!"
    $s2 = "document.write(unescape('%3C%68%74%6D%6C%3E%3C%62%6F%64%79%3E%3C%53%43%52%49%50%"
  condition:
    1 of them
}