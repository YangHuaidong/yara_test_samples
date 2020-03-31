rule WebShell_BackDoor_Unlimit_Fso_S_Remview_A_1265 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file remview.php"
    family = "Fso"
    hacker = "None"
    hash = "b4a09911a5b23e00b55abe546ded691c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fso.S.Remview.A"
    threattype = "BackDoor"
  strings:
    $s2 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\""
    $s3 = "         echo \"<script>str$i=\\\"\".str_replace(\"\\\"\",\"\\\\\\\"\",str_replace(\"\\\\\",\"\\\\\\\\\""
    $s4 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n<"
  condition:
    all of them
}