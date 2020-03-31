rule Trojan_Win32_Havex_B_735
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Havex.B"
		threattype = "BackDoor"
		family = "Havex"
		hacker = "None"
		refer = "875b0702ef3cc2d909ecf720bb4079c2"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-06"
		description = "None"

	strings:		
		$s0 = "9FPLbZG9h0DNBTjWDqyoyQP6Hy7r0ty"
		$s1 = "naTmm9y6IAQ2JZpTFhW1WVqC6a8sipU62zO94YwwqtThm"
		$s3 = "6zqUVoaA2DfbTyIoP8y1"
		$s4 = "Q5MxLfimzeQFgJvk"
		$s5 = "AGTwLoad"
		$s6 = "AGTwRec"
	condition:
		all of them
}