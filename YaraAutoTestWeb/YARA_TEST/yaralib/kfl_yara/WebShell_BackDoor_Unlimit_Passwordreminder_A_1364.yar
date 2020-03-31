rule WebShell_BackDoor_Unlimit_Passwordreminder_A_1364 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file PasswordReminder.exe"
    family = "Passwordreminder"
    hacker = "None"
    hash = "ea49d754dc609e8bfa4c0f95d14ef9bf"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Passwordreminder.A"
    threattype = "BackDoor"
  strings:
    $s3 = "The encoded password is found at 0x%8.8lx and has a length of %d."
  condition:
    all of them
}