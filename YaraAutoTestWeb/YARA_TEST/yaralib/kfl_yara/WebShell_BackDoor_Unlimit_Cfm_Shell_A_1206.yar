rule WebShell_BackDoor_Unlimit_Cfm_Shell_A_1206 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file shell.cfm"
    family = "Cfm"
    hacker = "None"
    hash = "885e1783b07c73e7d47d3283be303c9719419b92"
    judge = "unknown"
    reference = "http://laudanum.inguardians.com/"
    threatname = "WebShell[BackDoor]/Unlimit.Cfm.Shell.A"
    threattype = "BackDoor"
  strings:
    $s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii
  condition:
    filesize < 20KB and 2 of them
}