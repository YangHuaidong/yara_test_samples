rule WebShell_BackDoor_Unlimit_Webshell_Asp_Zehir4_A_1519 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file zehir4.asp"
    family = "Webshell"
    hacker = "None"
    hash = "7f4e12e159360743ec016273c3b9108c"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Zehir4.A"
    threattype = "BackDoor"
  strings:
    $s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/"
  condition:
    all of them
}