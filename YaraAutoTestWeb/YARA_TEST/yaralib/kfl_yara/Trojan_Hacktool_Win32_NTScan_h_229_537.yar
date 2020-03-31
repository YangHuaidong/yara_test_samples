import "pe"
rule Trojan_Hacktool_Win32_NTScan_h_229_537 
{

   meta:
        judge = "suspicious"
        threatname = "Trojan[Hacktool]/Win32.NTScan.h"
        threattype = "Hacktool"
        family = "NTScan"
        hacker = "None"
        author = "Florian Roth-mqx"
        refer = "254d87bdd1f358de19ec50a3203d771a"
        comment = "None"
        date = "2018-07-19"
        description = "PassCV Malware mentioned in Cylance Report"

   strings:
      $x1 = "NTscan.EXE" fullword wide
      $x2 = "NTscan Microsoft " fullword wide
      $s1 = "admin$" fullword ascii
   
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}