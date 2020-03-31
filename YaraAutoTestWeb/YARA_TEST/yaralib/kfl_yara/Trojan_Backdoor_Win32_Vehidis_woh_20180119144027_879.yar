rule Trojan_Backdoor_Win32_Vehidis_woh_20180119144027_879 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Vehidis.woh"
		threattype = "BackDoor"
		family = "Vehidis"
		hacker = "None"
		refer = "39c9900aa3218098fa42be97ea7076c9"
		description = "None"
		comment = "None"
		author = "mqx"
		date = "2017-01-11"
	strings:
		$s0 = "ERESFxcQFBUeRhMTEhIeXkVUIA=="
		$s1 = "%s-SCBar-%d"
		$s2 = "Server.dat"

	condition:
		all of them
}
