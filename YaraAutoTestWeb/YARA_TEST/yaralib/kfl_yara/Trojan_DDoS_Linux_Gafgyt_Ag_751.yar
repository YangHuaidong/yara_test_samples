rule Trojan_DDoS_Linux_Gafgyt_Ag_751
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Ag"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "2cd9875ea9ca968a95f475c99ee7e971,10ed17a5614075ff29dcf8cc62164939,bcc1b37692dc4a071c75b9abb18df8a0"
		author = "Fariin"
		comment = "None"
		date = "2018-11-26"
		description = "None"
	strings:
		$s0 = "[ Yakuza ] Infecting"
		$s1 = "IP: %s || Port: 23 || Username: %s || Password: %s"
		$s2 = "[\x1B[96mBOT JOINED\x1B[97m] Arch: \x1B"

	condition:
		all of them

}