rule WebShell_BackDoor_Unlimit_Webshell_Phpshell_2_1_Pwhash_A_1696 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file pwhash.php"
    family = "Webshell"
    hacker = "None"
    hash = "ba120abac165a5a30044428fac1970d8"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Phpshell.2.1.Pwhash.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi"
    $s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\","
  condition:
    1 of them
}