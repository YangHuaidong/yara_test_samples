rule WebShell_BackDoor_Unlimit_Aspx_Shell_A {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file shell.aspx"
    family = "Aspx"
    hacker = "None"
    hash = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Aspx.Shell.A"
    threattype = "BackDoor"
  strings:
    $s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii /* PEStudio Blacklist: strings */
    $s2 = "remoteIp = Request.UserHostAddress;" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "<form method=\"post\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 20KB and all of them
}