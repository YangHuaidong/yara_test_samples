rule WebShell_BackDoor_Unlimit_Lurm_Safemod_On_Cgi_A_1314 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file lurm_safemod_on.cgi.txt"
    family = "Lurm"
    hacker = "None"
    hash = "5ea4f901ce1abdf20870c214b3231db3"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Lurm.Safemod.On.Cgi.A"
    threattype = "BackDoor"
  strings:
    $s0 = "Network security team :: CGI Shell" fullword
    $s1 = "#########################<<KONEC>>#####################################" fullword
    $s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword
  condition:
    1 of them
}