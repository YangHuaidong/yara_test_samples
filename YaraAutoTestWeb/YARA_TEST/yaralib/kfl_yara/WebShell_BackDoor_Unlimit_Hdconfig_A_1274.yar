rule WebShell_BackDoor_Unlimit_Hdconfig_A_1274 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file HDConfig.exe"
    family = "Hdconfig"
    hacker = "None"
    hash = "7d60e552fdca57642fd30462416347bd"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hdconfig.A"
    threattype = "BackDoor"
  strings:
    $s0 = "An encryption key is derived from the password hash. "
    $s3 = "A hash object has been created. "
    $s4 = "Error during CryptCreateHash!"
    $s5 = "A new key container has been created."
    $s6 = "The password has been added to the hash. "
  condition:
    all of them
}