rule Trojan_Backdoor_Win32_Kazy_Lmko_62_118 
{
   
   meta:
      judge = "black"
			threatname = "Trojan[Backdoor]/Win32.Kazy.Lmko"
			threattype = "Backdoor"
			family = "Kazy"
			hacker = "None"
			comment = "None"
			date = "2015-05-14"
			author = "Florian Roth--DC"
			description = "Detects BlackEnergy 2 Malware" 
			refer = "ac1a265be63be7122b94c63aabcc9a66"
			
		
			
   strings:
      $s0 = "<description> Windows system utility service  </description>" fullword ascii
      $s1 = "WindowsSysUtility - Unicode" fullword wide
      $s2 = "msiexec.exe" fullword wide
      $s3 = "WinHelpW" fullword ascii
      $s4 = "ReadProcessMemory" fullword ascii
   
   condition:
      uint16(0) == 0x5a4d and filesize < 250KB and all of ($s*)
}