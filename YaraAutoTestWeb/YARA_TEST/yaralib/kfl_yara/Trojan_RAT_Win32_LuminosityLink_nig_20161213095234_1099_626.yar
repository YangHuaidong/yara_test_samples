rule Trojan_RAT_Win32_LuminosityLink_nig_20161213095234_1099_626 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.LuminosityLink.nig"
		threattype = "rat"
		family = "LuminosityLink"
		hacker = "None"
		refer = "0be623f26a2aeb2a4292a67cb6fd9fed"
		description = "None"
		comment = "None"
		author = "DJW, Kevin Breen <kevin@techanarchy.net>"
		date = "2016-12-07"
	strings:
		$a = "SMARTLOGS" wide
		$b = "RUNPE" wide
		$c = "b.Resources" wide
		$d = "CLIENTINFO*" wide
		$e = "Invalid Webcam Driver Download URL, or Failed to Download File!" wide
		$f = "Proactive Anti-Malware has been manually activated!" wide
		$g = "REMOVEGUARD" wide
		$h = "C0n1f8" wide
		$i = "Luminosity" wide
		$j = "LuminosityCryptoMiner" wide
		$k = "MANAGER*CLIENTDETAILS*" wide

	condition:
		6 of them
}
