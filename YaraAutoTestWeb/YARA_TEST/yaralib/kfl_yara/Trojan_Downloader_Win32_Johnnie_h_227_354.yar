import "pe"
rule Trojan_Downloader_Win32_Johnnie_h_227_354
{

   meta:
        judge = "black"
        threatname = "Trojan[downloader]/Win32.Johnnie.h"
        threattype = "downloader"
        family = "Johnnie"
        hacker = "None"
        author = "Florian Roth-mqx"
        refer = "5919b59b61b3807b18be08a35d7c4633,d4bc7b620ab9ee2ded2ac783ad77dd6d"
        comment = "None"
        date = "2018-07-19"
        description = "PassCV Malware mentioned in Cylance Report"

   strings:
        $x1 = "F:\\Excalibur\\Excalibur\\" ascii
        $x2 = "Excalibur\\bin\\Shell.pdb" ascii
        $x3 = "SaberSvc.exe" wide
        $s1 = "BBB.exe" fullword wide
        $s2 = "AAA.exe" fullword wide
   
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of ($x*) or all of ($s*) ) or 3 of them
}