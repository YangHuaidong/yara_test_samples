rule WebShell_BackDoor_Unlimit_Webshell_Asp_Tool_A_1516 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file tool.asp"
    family = "Webshell"
    hacker = "None"
    hash = "4ab68d38527d5834e9c1ff64407b34fb"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Asp.Tool.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\""
    $s3 = "Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" "
    $s9 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas"
  condition:
    2 of them
}