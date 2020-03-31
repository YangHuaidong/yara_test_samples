rule Trojan_Backdoor_Win32_BlackEnergy2_a_1067
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BlackEnergy2.a"
		threattype = "ICS,Backdoor"
		family = "BlackEnergy2"
		hacker = "None"
		refer = "ac1a265be63be7122b94c63aabcc9a66"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
   strings:
      $s0 = "<description> Windows system utility service  </description>" fullword ascii
      $s1 = "WindowsSysUtility - Unicode" fullword wide
      $s2 = "msiexec.exe" fullword wide
      $s3 = "WinHelpW" fullword ascii
      $s4 = "ReadProcessMemory" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 250KB and all of ($s*)
}