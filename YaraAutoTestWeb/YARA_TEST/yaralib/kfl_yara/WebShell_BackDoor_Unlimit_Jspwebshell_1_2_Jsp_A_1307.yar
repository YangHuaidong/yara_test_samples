rule WebShell_BackDoor_Unlimit_Jspwebshell_1_2_Jsp_A_1307 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file JspWebshell 1.2.jsp.txt"
    family = "Jspwebshell"
    hacker = "None"
    hash = "70a0ee2624e5bbe5525ccadc467519f6"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Jspwebshell.1.2.Jsp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "JspWebshell"
    $s1 = "CreateAndDeleteFolder is error:"
    $s2 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c"
    $s3 = "String _password =\"111\";"
  condition:
    2 of them
}