rule Trojan_DDoS_Win32_StormDDoS_7_20170316094902_1029_324 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.7"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "0fdbaaa4f7facb08d00280d3d07a1158"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-09"
	strings:
		$s0 = " /c del"
		$s1 = "SYSTEM\\CurrentControlSet\\Services\\"
		$s2 = " > nul"
		$s3 = "%c%c%c%c%c%c.exe" fullword
		$s4 = { 2b 40 3e 68 38 6f }
		$s5 = { 2f 0d 6f 5a 73 }
		$s6 = { 3b 23 58 52 6d 45 }
		$s7 = { 6f 40 58 38 08 5a }
		$s8 = { 5e 37 62 48 75 }
		$s9 = { 4d 7d 58 55 56 }

	condition:
		($s0 and $s1 and $s2 and $s3) or ($s4 and $s5 and $s6 and $s7 and $s8 and $s9)
}
