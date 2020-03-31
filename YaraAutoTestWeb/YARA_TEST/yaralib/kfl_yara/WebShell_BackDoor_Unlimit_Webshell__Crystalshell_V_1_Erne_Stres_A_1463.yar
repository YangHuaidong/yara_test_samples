rule WebShell_BackDoor_Unlimit_Webshell__Crystalshell_V_1_Erne_Stres_A_1463 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, erne.php, stres.php"
    family = "Webshell"
    hacker = "None"
    hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
    hash1 = "6eb4ab630bd25bec577b39fb8a657350bf425687"
    hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell..Crystalshell.V.1.Erne.Stres.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<input type='submit' value='  open (shill.txt) '>" fullword
    $s4 = "var_dump(curl_exec($ch));" fullword
    $s7 = "if(empty($_POST['Mohajer22'])){" fullword
    $s10 = "$m=$_POST['curl'];" fullword
    $s13 = "$u1p=$_POST['copy'];" fullword
    $s14 = "if(empty(\\$_POST['cmd'])){" fullword
    $s15 = "$string = explode(\"|\",$string);" fullword
    $s16 = "$stream = imap_open(\"/etc/passwd\", \"\", \"\");" fullword
  condition:
    5 of them
}