rule WebShell_BackDoor_Unlimit_Wh_Bindshell_Py_A_1770 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file wh_bindshell.py.txt"
    family = "Wh"
    hacker = "None"
    hash = "fab20902862736e24aaae275af5e049c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Wh.Bindshell.Py.A"
    threattype = "BackDoor"
  strings:
    $s0 = "#Use: python wh_bindshell.py [port] [password]"
    $s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"" fullword
    $s3 = "#bugz: ctrl+c etc =script stoped=" fullword
  condition:
    1 of them
}