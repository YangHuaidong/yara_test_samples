rule WebShell_BackDoor_Unlimit_Webshell_2_520_Icesword_Job_Ma1_A_1475 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "64a3bf9142b045b9062b204db39d4d57"
    hash1 = "9abd397c6498c41967b4dd327cf8b55a"
    hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
    hash3 = "56c005690da2558690c4aa305a31ad37"
    hash4 = "532b93e02cddfbb548ce5938fe2f5559"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.2.520.Icesword.Job.Ma1.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>" fullword
    $s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />" fullword
    $s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />" fullword
  condition:
    2 of them
}