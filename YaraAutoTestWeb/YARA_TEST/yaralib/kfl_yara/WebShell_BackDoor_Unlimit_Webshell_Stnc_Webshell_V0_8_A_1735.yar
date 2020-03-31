rule WebShell_BackDoor_Unlimit_Webshell_Stnc_Webshell_V0_8_A_1735 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
    family = "Webshell"
    hacker = "None"
    hash = "52068c9dff65f1caae8f4c60d0225708612bb8bc"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Stnc.Webshell.V0.8.A"
    threattype = "BackDoor"
  strings:
    $s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
    $s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()"
    $s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw"
  condition:
    2 of them
}