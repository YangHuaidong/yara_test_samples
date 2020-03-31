rule WebShell_BackDoor_Unlimit_Webshell_Caidao_Shell_Hkmjj_A_1546 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file hkmjj.asp"
    family = "Webshell"
    hacker = "None"
    hash = "e7b994fe9f878154ca18b7cde91ad2d0"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Caidao.Shell.Hkmjj.A"
    threattype = "BackDoor"
  strings:
    $s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
  condition:
    all of them
}