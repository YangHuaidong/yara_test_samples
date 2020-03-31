rule Trojan_RAT_Win32_TSGeneric_Rvx_724
{
    meta:
	    judge = "black"
		threatname = "Trojan[RAT]/Win32.TSGeneric.Rvx"
		threattype = "RAT"
		family = "TSGeneric"
		hacker = "None"
		refer = "b741122c386e2150ccae51cc62b4e3c4"
		author = "xc"
		comment = "None"
		date = "2017-08-31"
		description = "None"
	strings:
	    $s0 = "Shiela"
		$s1 = "ShielKwhr"
		$s2 = "Pinnotere"
		$s3 = "Flashy1"
		$s4 = "Valvula8"
		$s5 = "Rvx.dll"
		$s6 = "Xierox"
		$s7 = "f2222222222f"
	condition:
	    7 of them		
}