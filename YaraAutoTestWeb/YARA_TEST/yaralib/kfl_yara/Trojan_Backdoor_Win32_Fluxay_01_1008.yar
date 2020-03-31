rule Trojan_Backdoor_Win32_Fluxay_01_1008
{
	meta:
	    judge = "black"
	    threatname = "Trojan[Backdoor]/Win32.Fluxay.01"
	    threattype = "Backdoor"
	    family = "Fluxay"
	    hacker = "None"
	    refer = "028a2b538638f86326b056999becc960"
	    comment = "None"
		description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
		author = "Florian Roth -lz"
		date = "2015/03/30"
		
		
	strings:
		$s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
		$s11 = ";DATABASE=master" fullword ascii
		$s12 = "xp_cmdshell '" fullword ascii
		$s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii
	condition:
		all of them
}