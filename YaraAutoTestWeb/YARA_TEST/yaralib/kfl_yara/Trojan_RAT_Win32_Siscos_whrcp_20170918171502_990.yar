rule Trojan_RAT_Win32_Siscos_whrcp_20170918171502_990 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Siscos.whrcp"
		threattype = "rat"
		family = "Siscos"
		hacker = "None"
		refer = "006e0674bd7847c2467589179c36f59f"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-13"
	strings:
		$s0 = "cgi_ger_noprpair" nocase wide ascii
		$s1 = "SSBKSPT" nocase wide ascii
		$s2 = "npogpam" nocase wide ascii

	condition:
		all of them
}
