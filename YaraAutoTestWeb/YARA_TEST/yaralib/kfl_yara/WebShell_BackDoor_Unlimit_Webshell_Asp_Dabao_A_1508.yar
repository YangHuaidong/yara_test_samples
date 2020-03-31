rule WebShell_BackDoor_Unlimit_Webshell_Asp_Dabao_A_1508 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file dabao.asp"
    family = "Webshell"
    hacker = "None"
    hash = "3919b959e3fa7e86d52c2b0a91588d5d"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Dabao.A"
    threattype = "BackDoor"
  strings:
    $s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &"
    $s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-"
  condition:
    all of them
}