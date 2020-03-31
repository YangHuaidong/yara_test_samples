rule WebShell_BackDoor_Unlimit_Reader_Asp_A_1402 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Reader.asp.txt"
    family = "Reader"
    hacker = "None"
    hash = "ad1a362e0a24c4475335e3e891a01731"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Reader.Asp.A"
    threattype = "BackDoor"
  strings:
    $s1 = "Mehdi & HolyDemon"
    $s2 = "www.infilak."
    $s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%"
  condition:
    2 of them
}