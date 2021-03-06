rule WebShell_BackDoor_Unlimit_Webshell_C99_Locus7S_A_1536 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file c99_locus7s.php"
    family = "Webshell"
    hacker = "None"
    hash = "d413d4700daed07561c9f95e1468fb80238fbf3c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.C99.Locus7S.A"
    threattype = "BackDoor"
  strings:
    $s8 = "$encoded = base64_encode(file_get_contents($d.$f)); " fullword
    $s9 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y"
    $s10 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq"
    $s11 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server " fullword
    $s19 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd " fullword
  condition:
    2 of them
}