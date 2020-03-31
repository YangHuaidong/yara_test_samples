rule Trojan_Backdoor_Win32_Minaps_A_2_20170110095453_927_133 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Minaps.A"
		threattype = "rat"
		family = "Minaps"
		hacker = "None"
		refer = "6b14351ba454bcbfccbaf213f83a1282"
		description = "CommentCrew-threat-apt1"
		comment = "None"
		author = "AlienVault Labs"
		date = "2016-12-27"
	strings:
		$s0 = "miniasp" wide ascii
		$s1 = "wakeup=" wide ascii
		$s2 = "download ok!" wide ascii
		$s3 = "command is null!" wide ascii
		$s4 = "device_input.asp?device_t=" wide ascii

	condition:
		all of them
}
