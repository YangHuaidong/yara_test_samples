rule Trojan_Backdoor_Win32_Sdbot_aerkcp_20170918171441_872 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Sdbot.aerkcp"
		threattype = "BackDoor"
		family = "Sdbot"
		hacker = "None"
		refer = "1aa8049840f7ea8911b78b937c5ee78e"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-14"
	strings:
		$s0 = "SeBackupPrivilege" nocase wide ascii
		$s1 = "COMMAND_DDOS_GET" nocase wide ascii
		$s2 = "config.ini" nocase wide ascii

	condition:
		all of them
}
