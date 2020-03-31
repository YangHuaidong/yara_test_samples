rule Trojan_DDoS_Win32_Macri_a_693
{
	meta:
	    judge = "black"
		threatname = "Trojan[DDoS]/Win32.Macri.a"
		threattype = "DDoS"
		family = "Macri"
		hacker = "None"
		refer = "1106866f1b189f6f25aede9251d07664"
		author = "mqx"
		comment = "None"
		date = "2017-10-18"
		description = "None"
	strings:
	    $s0 = "Wave.exe"
		$s1 = "CWaveDoc"
		$s2 = "StartupServer"
	condition:
	    all of them	
}