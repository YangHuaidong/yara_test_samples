import "pe"
rule Trojan_Backdoor_Win32_Zxshell_A_224_251
{

   meta:
        judge = "black"
        threatname = "Trojan[backdoor]/Win32.Zxshell.A"
        threattype = "backdoor"
        family = "Zxshell"
        hacker = "None"
        author = "Florian Roth-mqx"
        refer = "c176286e35c0629ea526e299c369dc6e"
        comment = "None"
        date = "2018-07-19"
        description = "PassCV Malware mentioned in Cylance Report"

   strings:
      $x1 = "NXKILL" fullword wide
      $s1 = "2OLE32.DLL" fullword ascii
      $s2 = "localspn.dll" fullword wide
      $s3 = "!This is a Win32 program." fullword ascii
   
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and $x1 and 2 of ($s*) )
}