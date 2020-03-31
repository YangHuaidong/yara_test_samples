rule Trojan_Backdoor_Linux_Tsunami_gen_20161213095111_899_33 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Tsunami.gen"
		threattype = "BackDoor"
		family = "Tsunami"
		hacker = "None"
		refer = "EA52FBA3615BE9698EFE2F4DB5033688"
		description = "None"
		comment = "None"
		author = "dongjianwu, @benkow_"
		date = "2016-11-29"
	strings:
		$a = "PRIVMSG %s :[STD]Hitting %s"
		$b = "NOTICE %s :TSUNAMI <target> <secs>"
		$c = "NOTICE %s :I'm having a problem resolving my host, someone will have to SPOOFS me manually."

	condition:
		$a or $b or $c
}
