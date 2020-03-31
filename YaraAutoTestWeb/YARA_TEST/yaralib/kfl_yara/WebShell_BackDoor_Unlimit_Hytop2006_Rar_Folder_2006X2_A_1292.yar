rule WebShell_BackDoor_Unlimit_Hytop2006_Rar_Folder_2006X2_A_1292 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2006X2.exe"
    family = "Hytop2006"
    hacker = "None"
    hash = "cc5bf9fc56d404ebbc492855393d7620"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hytop2006.Rar.Folder.2006X2.A"
    threattype = "BackDoor"
  strings:
    $s2 = "Powered By "
    $s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this."
  condition:
    all of them
}