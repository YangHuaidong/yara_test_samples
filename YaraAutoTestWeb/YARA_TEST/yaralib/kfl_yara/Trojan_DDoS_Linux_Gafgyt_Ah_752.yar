rule Trojan_DDoS_Linux_Gafgyt_Ah_752
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Ah"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "9dea9a05e6d617bd97e92b725ba697a6"
		author = "Fariin"
		comment = "None"
		date = "2018-11-26"
		description = "None"
	strings:
		$s0 = "\x1B[1;37m[\x1B[0;31mBoatnet\x1B[1;37m]\x1B[0;37m"
		$s1 = "\x1B[1;31m\x1B[43mDevice Infected\x1B[40m\x1B[0m"
		$s2 = "\x1B[0;31m\x1B[43mINFECTED\x1B[40m\x1B[0m \x1B[0;31m"
		$s3 = "\x1B[1;37m[\x1B[0;31mM2M\x1B[1;37m] \x1B[1;36mDevices"
		$s4 = "%sWelcome to the botnet [%s:%s:%d cores] :)%s"
		$s5 = "\x1B[1;37m[\x1B[0;31mDemon\x1B[1;37m]\x1B[0;37m"

	condition:
		any of them

}