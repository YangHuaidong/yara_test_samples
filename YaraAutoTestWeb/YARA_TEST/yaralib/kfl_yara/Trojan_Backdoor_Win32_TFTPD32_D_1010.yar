rule Trojan_Backdoor_Win32_TFTPD32_D_1010
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.TFTPD32.D"
		threattype = "Backdoor"
		family = "TFTPD32"
		hacker = "None"
		refer = "e6efe695f995707839233180cf554f64"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file TFTPD32.EXE"
		author = "Florian Roth -lz"
		date = "23.11.14"
		
	strings:
		$s0 = " http://arm.533.net" fullword ascii
		$s1 = "Tftpd32.hlp" fullword ascii
		$s2 = "Timeouts and Ports should be numerical and can not be 0" fullword ascii
		$s3 = "TFTPD32 -- " fullword wide
		$s4 = "%d -- %s" fullword ascii
		$s5 = "TIMEOUT while waiting for Ack block %d. file <%s>" fullword ascii
		$s12 = "TftpPort" fullword ascii
		$s13 = "Ttftpd32BackGround" fullword ascii
		$s17 = "SOFTWARE\\TFTPD32" fullword ascii
	condition:
		all of them
}
