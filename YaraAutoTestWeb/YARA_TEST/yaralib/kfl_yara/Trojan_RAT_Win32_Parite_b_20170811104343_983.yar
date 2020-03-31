rule Trojan_RAT_Win32_Parite_b_20170811104343_983 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Parite.b"
		threattype = "rat"
		family = "Parite"
		hacker = "None"
		refer = "31c9187bdbf3c676a726df2ead456f31"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-07-25"
	strings:
		$s0 = "Ndxr/" nocase wide ascii
		$s1 = "FWX&S" nocase wide ascii
		$s2 = "0JV37" nocase wide ascii
		$s3 = "Install.dat" nocase wide ascii

	condition:
		all of them
}
