rule Trojan_Backdoor_Win32_Plugx_A_1_20161213095240_937_162 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Plugx.A"
		threattype = "rat"
		family = "Plugx"
		hacker = "None"
		refer = "534d28ad55831c04f4a7a8ace6dd76c3"
		description = "PlugX RAT,https://github.com/mattulm/IR-things/blob/master/volplugs/plugx.py"
		comment = "None"
		author = "ean-Philippe Teissier / @Jipe_"
		date = "2014-05-13"
	strings:
		$s0 = { 47 55 4c 50 00 00 00 00 }
		$s1 = "/update?id=%8.8x"
		$s2 = { bb 33 33 33 33 2b }
		$s3 = { bb 44 44 44 44 2b }
		$s4 = "Proxy-Auth:"
		$s5 = { 68 a0 02 00 00 }
		$s6 = { c1 8f 3a 71 }

	condition:
		$s0 at 0 or $s1 or (($s4 or $s5) and (($s2 and $s3) or $s6))
}
