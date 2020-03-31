rule WebShell_BackDoor_Unlimit_Asp_Proxy_A {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file proxy.asp"
    family = "Asp"
    hacker = "None"
    hash = "51e97040d1737618b1775578a772fa6c5a31afd8"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Asp.Proxy.A"
    threattype = "BackDoor"
  strings:
    $s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
    $s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii /* PEStudio Blacklist: strings */
    $s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii /* PEStudio Blacklist: strings */
    $s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 50KB and all of them
}