rule WebShell_BackDoor_Unlimit_Phyton_Shell_Py_A_1392 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Phyton Shell.py.txt"
    family = "Phyton"
    hacker = "None"
    hash = "92b3c897090867c65cc169ab037a0f55"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Phyton.Shell.Py.A"
    threattype = "BackDoor"
  strings:
    $s1 = "sh_out=os.popen(SHELL+\" \"+cmd).readlines()" fullword
    $s2 = "#   d00r.py 0.3a (reverse|bind)-shell in python by fQ" fullword
    $s3 = "print \"error; help: head -n 16 d00r.py\"" fullword
    $s4 = "print \"PW:\",PW,\"PORT:\",PORT,\"HOST:\",HOST" fullword
  condition:
    1 of them
}