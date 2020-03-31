rule Trojan_Backdoor_Win32_Xtrat_B_20161213095250_956_242 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Xtrat.B"
		threattype = "rat"
		family = "Xtrat"
		hacker = "None"
		refer = "fcba94a000d1745304b3e4dcde0e6ec4"
		description = "Xtreme RAT"
		comment = "None"
		author = "botherder https://github.com/botherder"
		date = "2016-12-08"
	strings:
		$s0 = /(X)tremeKeylogger/ wide ascii
		$s1 = /(X)tremeRAT/ wide ascii
		$s2 = /(X)TREMEUPDATE/ wide ascii
		$s3 = /(S)TUBXTREMEINJECTED/ wide ascii
		$s4 = /(U)nitConfigs/ wide ascii
		$s5 = /(U)nitGetServer/ wide ascii
		$s6 = /(U)nitKeylogger/ wide ascii
		$s7 = /(U)nitCryptString/ wide ascii
		$s8 = /(U)nitInstallServer/ wide ascii
		$s9 = /(U)nitInjectServer/ wide ascii
		$s10 = /(U)nitBinder/ wide ascii
		$s11 = /(U)nitInjectProcess/ wide ascii

	condition:
		5 of them
}
