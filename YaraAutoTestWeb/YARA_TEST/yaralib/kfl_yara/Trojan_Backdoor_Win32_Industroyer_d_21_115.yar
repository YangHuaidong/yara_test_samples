rule Trojan_Backdoor_Win32_Industroyer_d_21_115 
{
   meta:
      judge = "black"
			threatname = "Trojan[Backdoor]/Win32.Industroyer.d"
			threattype = "Backdoor"
			family = "Industroyer"
			hacker = "None"
			comment = "https://goo.gl/x81cSy Industroyer_Malware_1"
			date = "2017-06-13"
			author = "Florian Roth-DC"
			description = "Detects Industroyer related malware " 
			refer = "7a7ace486dbb046f588331a08e869d58"
      hash2 = "ab17f2b17c57b731cb930243589ab0cf"
   strings:
      $s1 = "haslo.exe" fullword ascii
      $s2 = "SYSTEM\\CurrentControlSet\\Services\\%ls" fullword wide
      $s3 = "SYS_BASCON.COM" fullword wide
      $s4 = "*.pcmt" fullword wide
      $s5 = "*.pcmi" fullword wide
      $x1 = { 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5C 00 25 00 6C 00 73 00 00 00 49 00 6D 00 61 00 67 00 65 00 50 00 61 00 74 00 68 00 00 00 43 00 3A 00 5C 00 00 00 44 00 3A 00 5C 00 00 00 45 00 3A 00 5C 00 00 00 }
      $x2 = "haslo.dat\x00Crash"
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) or 2 of them )
}