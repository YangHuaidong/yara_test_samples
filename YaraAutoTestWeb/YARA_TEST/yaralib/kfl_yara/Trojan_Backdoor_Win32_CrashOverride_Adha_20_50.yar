rule Trojan_Backdoor_Win32_CrashOverride_Adha_20_50 
{
   meta:
      judge = "black"
			threatname = "Trojan[Backdoor]/Win32.CrashOverride.A!dha"
			threattype = "Backdoor"
			family = "CrashOverride"
			hacker = "None"
			comment = "https://goo.gl/x81cSy Industroyer_Malware_1"
			date = "2017-06-13"
			author = "Florian Roth-DC"
			description = "Detects Industroyer related malware" 
			refer = "11a67ff9ad6006bd44f08bcc125fb61e"
      hash2 = "f67b65b9346ee75a26f491b70bf6091b"
      hash3 = "ff69615e3a8d7ddcdc4b7bf94d6c7ffb"
      hash4 = "fc4fe1b933183c4c613d34ffdb5fe758"
      
      
      
   strings:
      $x1 = "sc create %ls type= own start= auto error= ignore binpath= \"%ls\" displayname= \"%ls\"" fullword wide
      $x2 = "10.15.1.69:3128" fullword wide

      $s1 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; InfoPath.1)" fullword wide
      $s2 = "/c sc stop %s" fullword wide
      $s3 = "sc start %ls" fullword wide
      $s4 = "93.115.27.57" fullword wide
      $s5 = "5.39.218.152" fullword wide
      $s6 = "tierexe" fullword wide
      $s7 = "comsys" fullword wide
      $s8 = "195.16.88.6" fullword wide
      $s9 = "TieringService" fullword wide

      $a1 = "TEMP\x00\x00DEF" fullword wide
      $a2 = "TEMP\x00\x00DEF-C" fullword wide
      $a3 = "TEMP\x00\x00DEF-WS" fullword wide
      $a4 = "TEMP\x00\x00DEF-EP" fullword wide
      $a5 = "TEMP\x00\x00DC-2-TEMP" fullword wide
      $a6 = "TEMP\x00\x00DC-2" fullword wide
      $a7 = "TEMP\x00\x00CES-McA-TEMP" fullword wide
      $a8 = "TEMP\x00\x00SRV_WSUS" fullword wide
      $a9 = "TEMP\x00\x00SRV_DC-2" fullword wide
      $a10 = "TEMP\x00\x00SCE-WSUS01" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of ($x*) or 3 of them or 1 of ($a*) ) or ( 5 of them )
}
