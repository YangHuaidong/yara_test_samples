rule Trojan_DDoS_Win32_Redlonam_A_804
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Redlonam.A"
		threattype = "DDoS"
		family = "Redlonam"
		hacker = "None"
		refer = "af9a14b68e0bb409841af167fb807308"
		author = "HuangYY"
		comment = "None"
		date = "2017-11-02"
		description = "None"

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