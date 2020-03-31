import "pe"
rule Trojan_Backdoor_Win32_Farfli_vui_223_89
{

   meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Farfli.vui"
        threattype = "Backdoor"
        family = "Farfli"
        hacker = "None"
        author = "Florian Roth-mqx"
        refer = "28af0e2520713b81659c95430220d2b9"
        comment = "None"
        date = "2018-07-19"
        description = "PassCV Malware mentioned in Cylance Report"

   strings:
      $x1 = "ncircTMPg" fullword ascii
      $x2 = "~SHELL#" fullword ascii
      $x3 = "N.adobe.xm" fullword ascii
      $s1 = "NEL32.DLL" fullword ascii
      $s2 = "BitLocker.exe" fullword wide
      $s3 = "|xtplhd" fullword ascii /* reversed goodware string 'dhlptx|' */
      $s4 = "SERVICECORE" fullword wide
      $s5 = "SHARECONTROL" fullword wide
   
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and 1 of ($x*) or all of ($s*) )
}