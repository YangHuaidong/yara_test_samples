rule WebShell_BackDoor_Unlimit_Webshell_2_520_Job_Jspwebshell_1_2_Ma1_Ma4_2_A_1477 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, JspWebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "64a3bf9142b045b9062b204db39d4d57"
    hash1 = "9abd397c6498c41967b4dd327cf8b55a"
    hash2 = "56c005690da2558690c4aa305a31ad37"
    hash3 = "70a0ee2624e5bbe5525ccadc467519f6"
    hash4 = "532b93e02cddfbb548ce5938fe2f5559"
    hash5 = "6e0fa491d620d4af4b67bae9162844ae"
    hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.2.520.Job.Jspwebshell.1.2.Ma1.Ma4.2.A"
    threattype = "BackDoor"
  strings:
    $s1 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {" fullword
    $s6 = "password = (String)session.getAttribute(\"password\");" fullword
    $s7 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231"
  condition:
    2 of them
}