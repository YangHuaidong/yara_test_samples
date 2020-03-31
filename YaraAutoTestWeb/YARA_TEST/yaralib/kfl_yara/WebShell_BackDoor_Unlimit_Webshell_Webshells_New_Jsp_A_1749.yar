rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Jsp_A_1749 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file JSP.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "495f1a0a4c82f986f4bdf51ae1898ee7"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Jsp.A"
    threattype = "BackDoor"
  strings:
    $s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i"
    $s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app"
    $s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest"
  condition:
    1 of them
}