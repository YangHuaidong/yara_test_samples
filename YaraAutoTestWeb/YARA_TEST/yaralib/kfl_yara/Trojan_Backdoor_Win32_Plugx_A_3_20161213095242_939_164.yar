rule Trojan_Backdoor_Win32_Plugx_A_3_20161213095242_939_164 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Plugx.A"
		threattype = "rat"
		family = "Plugx"
		hacker = "None"
		refer = "534d28ad55831c04f4a7a8ace6dd76c3"
		description = "PlugX Identifying Strings"
		comment = "None"
		author = "Seth Hardy"
		date = "2014-06-12"
	strings:
		$s0 = "boot.ldr" wide ascii
		$s1 = "d:\\work" nocase
		$s2 = "plug2.5"
		$s3 = "Plug3.0"
		$s4 = "Shell6"

	condition:
		$s0 or ($s1 and ($s2 or $s3 or $s4))
}
