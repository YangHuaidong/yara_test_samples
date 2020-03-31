rule WebShell_BackDoor_Unlimit_Webshell_Asp_Remexp_A_1514 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file RemExp.asp"
    family = "Webshell"
    hacker = "None"
    hash = "aa1d8491f4e2894dbdb91eec1abc2244"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Remexp.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques"
    $s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal"
  condition:
    all of them
}