rule WebShell_BackDoor_Unlimit_Zehir_4_Asp_A_1779 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Zehir 4.asp.txt"
    family = "Zehir"
    hacker = "None"
    hash = "7f4e12e159360743ec016273c3b9108c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Zehir.4.Asp.A"
    threattype = "BackDoor"
  strings:
    $s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time="
    $s4 = "<input type=submit value=\"Test Et!\" onclick=\""
  condition:
    1 of them
}