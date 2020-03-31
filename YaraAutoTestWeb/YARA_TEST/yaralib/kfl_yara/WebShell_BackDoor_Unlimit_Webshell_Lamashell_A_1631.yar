rule WebShell_BackDoor_Unlimit_Webshell_Lamashell_A_1631 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file lamashell.php"
    family = "Webshell"
    hacker = "None"
    hash = "b71181e0d899b2b07bc55aebb27da6706ea1b560"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Lamashell.A"
    threattype = "BackDoor"
  strings:
    $s0 = "if(($_POST['exe']) == \"Execute\") {" fullword
    $s8 = "$curcmd = $_POST['king'];" fullword
    $s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">" fullword
    $s18 = "<title>lama's'hell v. 3.0</title>" fullword
    $s19 = "_|_  O    _    O  _|_" fullword
    $s20 = "$curcmd = \"ls -lah\";" fullword
  condition:
    2 of them
}