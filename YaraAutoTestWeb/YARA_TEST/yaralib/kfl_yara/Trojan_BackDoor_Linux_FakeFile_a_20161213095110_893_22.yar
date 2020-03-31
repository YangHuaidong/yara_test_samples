rule Trojan_BackDoor_Linux_FakeFile_a_20161213095110_893_22 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Linux.FakeFile.a"
		threattype = "DDOS"
		family = "FakeFile"
		hacker = "none"
		refer = "ec301904171b1ebde3a57c952ae58a3a"
		description = "No root permissions to Linux Trojan backdoor"
		comment = "None"
		author = "dongjianwu"
		date = "2016-11-10"
	strings:
		$re0 = /User-Agent:.*MSIE.*Windows/
		$str0 = ".gconf/apps/gnome-common/gnome-common"

	condition:
		$str0 and $re0 and uint32(0) == 0x464c457f
}
