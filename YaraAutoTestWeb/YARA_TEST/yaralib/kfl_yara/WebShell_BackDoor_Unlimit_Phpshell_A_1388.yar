rule WebShell_BackDoor_Unlimit_Phpshell_A_1388 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file phpshell.php"
    family = "Phpshell"
    hacker = "None"
    hash = "1dccb1ea9f24ffbd085571c88585517b"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Phpshell.A"
    threattype = "BackDoor"
  strings:
    $s1 = "echo \"<input size=\\\"100\\\" type=\\\"text\\\" name=\\\"newfile\\\" value=\\\"$inputfile\\\"><b"
    $s2 = "$img[$id] = \"<img height=\\\"16\\\" width=\\\"16\\\" border=\\\"0\\\" src=\\\"$REMOTE_IMAGE_UR"
    $s3 = "$file = str_replace(\"\\\\\", \"/\", str_replace(\"//\", \"/\", str_replace(\"\\\\\\\\\", \"\\\\\", "
  condition:
    all of them
}