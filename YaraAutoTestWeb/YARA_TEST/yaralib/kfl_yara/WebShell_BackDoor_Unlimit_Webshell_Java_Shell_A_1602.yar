rule WebShell_BackDoor_Unlimit_Webshell_Java_Shell_A_1602 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Java Shell.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "36403bc776eb12e8b7cc0eb47c8aac83"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Java.Shell.A"
    threattype = "BackDoor"
  strings:
    $s4 = "public JythonShell(int columns, int rows, int scrollback) {" fullword
    $s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword
  condition:
    1 of them
}