rule WebShell_BackDoor_Unlimit_Jsp_Browser_Apt_Webshell_A_1301 {
  meta:
    author = "Spider"
    comment = "None"
    date = "10.10.2014"
    description = "VonLoesch JSP Browser used as web shell by APT groups - jsp File browser 1.1a"
    family = "Jsp"
    hacker = "None"
    judge = "unknown"
    reference = "None"
    score = 60
    threatname = "WebShell[BackDoor]/Unlimit.Jsp.Browser.Apt.Webshell.A"
    threattype = "BackDoor"
  strings:
    $a1a = "private static final String[] COMMAND_INTERPRETER = {\"" ascii
    $a1b = "cmd\", \"/C\"}; // Dos,Windows" ascii
    $a2 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" ascii
    $a3 = "ret.append(\"!!!! Process has timed out, destroyed !!!!!\");" ascii
  condition:
    all of them
}