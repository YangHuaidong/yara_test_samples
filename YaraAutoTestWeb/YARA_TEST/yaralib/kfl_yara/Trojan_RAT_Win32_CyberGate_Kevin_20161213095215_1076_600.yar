rule Trojan_RAT_Win32_CyberGate_Kevin_20161213095215_1076_600 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.CyberGate.Kevin"
		threattype = "rat"
		family = "CyberGate"
		hacker = "None"
		refer = "b1af7b4829465869ef1b236dc53eeb1e"
		description = "None"
		comment = "None"
		author = "djw, Kevin Breen <kevin@techanarchy.net>"
		date = "2016-12-01"
	strings:
		$string1 = { 23 23 23 23 40 23 23 23 23 e8 ee e9 f9 23 23 23 23 40 23 23 23 23 }
		$string2 = { 23 23 23 23 40 23 23 23 23 fa fd f0 ef f9 23 23 23 23 40 23 23 23 23 }
		$string3 = "EditSvr"
		$string4 = "TLoader"
		$string5 = "Stroks"
		$string6 = "####@####"
		$res1 = "XX-XX-XX-XX"
		$res2 = "CG-CG-CG-CG"

	condition:
		all of ($string*) and any of ($res*)
}
