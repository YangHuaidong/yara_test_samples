rule Trojan_Backdoor_Win32_Wakbot_A_20170110095456_952_234 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Wakbot.A"
		threattype = "rat"
		family = "Wakbot"
		hacker = "None"
		refer = "721adcea7f2fcd085c3a97b393c924a2"
		description = "None"
		comment = "None"
		author = "Seth Hardy <seth.hardy@utoronto.ca>"
		date = "2016-06-23"
	strings:
		$s0 = "fefj90"
		$s1 = "iamwaitingforu653890"
		$s2 = "watchevent29021803"
		$s3 = "THIS324NEWGAME"
		$s4 = "ms0ert.temp"
		$s5 = "\\mstemp.temp"

	condition:
		any of them
}
