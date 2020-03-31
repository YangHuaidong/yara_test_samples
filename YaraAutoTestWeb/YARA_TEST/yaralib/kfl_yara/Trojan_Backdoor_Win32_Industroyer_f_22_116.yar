rule Trojan_Backdoor_Win32_Industroyer_f_22_116 {
   meta:
      judge = "black"
			threatname = "Trojan[Backdoor]/Win32.Industroyer.f"
			threattype = "Backdoor"
			family = "Industroyer"
			hacker = "None"
			comment = "https://goo.gl/x81cSy Industroyer_Malware_1"
			date = "2017-06-13"
			author = "Florian Roth-DC"
			description = "Detects Industroyer related custom port scaner" 
			refer = "497de9d388d23bf8ae7230d80652af69"
      
      
   strings:
      $s1 = "!ZBfamily" fullword ascii
      $s2 = ":g/outddomo;" fullword ascii
      $s3 = "GHIJKLMNOTST" fullword ascii
      /* Decompressed File */
      $d1 = "Error params Arguments!!!" fullword wide
      $d2 = "^(.+?.exe).*\\s+-ip\\s*=\\s*(.+)\\s+-ports\\s*=\\s*(.+)$" fullword wide
      $d3 = "Exhample:App.exe -ip= 127.0.0.1-100," fullword wide
      $d4 = "Error IP Range %ls - %ls" fullword wide
      $d5 = "Can't closesocket." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of ($s*) or 2 of ($d*) )
}
