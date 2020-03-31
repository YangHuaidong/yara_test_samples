rule Trojan_Backdoor_Win32_Hanove_A_20170110095449_913_104 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Hanove.A"
		threattype = "rat"
		family = "Hanove"
		hacker = "None"
		refer = "12eec20e7f672370269a9ec53cd744fb"
		description = "None"
		comment = "None"
		author = "None"
		date = "2016-12-27"
	strings:
		$a = "Content-Disposition: form-data; name=\"uploaddir\""
		$b1 = "MBVDFRESCT"
		$b2 = "EMSCBVDFRT"
		$b3 = "EMSFRTCBVD"
		$b4 = "sendFile"
		$b5 = "BUGMAAL"
		$b6 = "sMAAL"
		$b7 = "SIMPLE"
		$b8 = "SPLIME"
		$b9 = "getkey.php"
		$c1 = "F39D45E70395ABFB8D8D2BFFC8BBD152"
		$c2 = "90B452BFFF3F395ABDC878D8BEDBD152"
		$c3 = "FFF3F395A90B452BB8BEDC878DDBD152"
		$c4 = "5A9DCB8FFF3F02B8B45BE39D152"
		$c5 = "5A902B8B45BEDCB8FFF3F39D152"
		$c6 = "78DDB5A902BB8FFF3F398B45BEDCD152"
		$c7 = "905ABEB452BFFFBDC878D83F39DBD152"
		$c8 = "D2BFFC8BBD152F3B8D89D45E70395ABF"
		$c9 = "8765F3F395A90B452BB8BEDC878"

	condition:
		$a and (1 of ($b*) or 1 of ($c*))
}
