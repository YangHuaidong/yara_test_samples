rule WebShell_BackDoor_Unlimit_Web_Inf_Web_A_1460 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file web.xml"
    family = "Web"
    hacker = "None"
    hash = "0251baed0a16c451f9d67dddce04a45dc26cb4a3"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Web.Inf.Web.A"
    threattype = "BackDoor"
  strings:
    $s1 = "<servlet-name>Command</servlet-name>" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii
  condition:
    filesize < 1KB and all of them
}