rule Trojan_DDoS_Win32_Agent_bo_RECYCLER_20170412094531_999_291 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Agent_bo.RECYCLER"
		threattype = "DDOS"
		family = "Agent_bo"
		hacker = "None"
		refer = "1b3ac889b1652f7981108c7815e229b0,c1c9361b3fa0c920e8f5df053a2d2868"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2017-03-31"
	strings:
		$s0 = "YSlOcppz" nocase wide ascii
		$s1 = "%ALLUSERSPROFILE%\\Start Menu\\Programs"	nocase wide ascii
		$s2 = "ZwWriteVirtualMemory" nocase wide ascii
		$s3 = "Shell Startup" nocase wide ascii
		$s4 = "explorer.exe" fullword
		$s5 = "flooding" nocase wide ascii
		$s6 = "ScmCreatedEvent" nocase wide ascii

	condition:
		5 of them
}
