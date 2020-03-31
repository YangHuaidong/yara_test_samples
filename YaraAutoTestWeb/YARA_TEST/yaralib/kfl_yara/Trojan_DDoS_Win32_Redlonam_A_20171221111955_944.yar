rule Trojan_DDoS_Win32_Redlonam_A_20171221111955_944 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Redlonam.A"
		threattype = "DDOS"
		family = "Redlonam"
		hacker = "None"
		refer = "af9a14b68e0bb409841af167fb807308"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-11-02"
	strings:
		$s0 = "tkMGWPHT4VcI0kba3q"
		$s1 = "zMdDhcNIfHAavGvbyk"
		$s2 = "E1vmiXiiHWgfLS2Rwv"
		$s3 = "MW18QVciVDgFxjNRnf"
		$s4 = "VO27RXR0dUaS5RhAb1"
		$s5 = "L6sHuRIeTIicHUBAj4"
		$s6 = "xT5CTvxRnrjbFX0YWn"
		$s7 = "MtQTRdLpDYMc9Sug8n"

	condition:
		5 of them
}
