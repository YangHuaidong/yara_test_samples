rule Trojan_Backdoor_Win32_Farfli_hex_20170811104317_858 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Farfli.hex"
		threattype = "BackDoor"
		family = "Farfli"
		hacker = "none"
		refer = "6b75286ff8aef529d02c7fad7d85a968"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-08-03"
	strings:
		$s0 = { c1 e9 1d c1 ea 1e 8b f0 83 e1 01 83 e2 01 c1 ee 1f a9 00 00 00 02 }
		$s1 = { 25 ff 00 00 00 c1 ea 18 33 cb 83 c6 04 }
		$s2 = { 25 ff 00 00 00 c1 ea 18 33 cb 83 ef 20 }

	condition:
		all of them
}
