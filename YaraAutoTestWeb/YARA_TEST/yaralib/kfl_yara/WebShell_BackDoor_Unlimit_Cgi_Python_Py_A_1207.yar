rule WebShell_BackDoor_Unlimit_Cgi_Python_Py_A_1207 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file cgi-python.py.txt"
    family = "Cgi"
    hacker = "None"
    hash = "0a15f473e2232b89dae1075e1afdac97"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Cgi.Python.Py.A"
    threattype = "BackDoor"
  strings:
    $s0 = "a CGI by Fuzzyman"
    $s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + "
    $s2 = "values = map(lambda x: x.value, theform[field])     # allows for"
  condition:
    1 of them
}