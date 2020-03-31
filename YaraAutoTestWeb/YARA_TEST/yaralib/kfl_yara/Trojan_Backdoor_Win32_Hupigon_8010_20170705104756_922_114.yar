rule Trojan_Backdoor_Win32_Hupigon_8010_20170705104756_922_114 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Hupigon.8010"
		threattype = "BackDoor"
		family = "Hupigon"
		hacker = "none"
		refer = "c5b4dcf58c018f14869f0bce96808767"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-27"
	strings:
		$s0 = "8010"
		$s2 = "59.110.162.132"
		$s3 = "#32770"

	condition:
		all of them
}
