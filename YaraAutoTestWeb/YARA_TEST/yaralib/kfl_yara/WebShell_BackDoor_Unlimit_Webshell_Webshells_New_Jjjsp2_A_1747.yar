rule WebShell_BackDoor_Unlimit_Webshell_Webshells_New_Jjjsp2_A_1747 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file JJJsp2.jsp"
    family = "Webshell"
    hacker = "None"
    hash = "5a9fec45236768069c99f0bfd566d754"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Webshells.New.Jjjsp2.A"
    threattype = "BackDoor"
  strings:
    $s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z"
    $s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ"
    $s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()"
    $s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase("
  condition:
    1 of them
}