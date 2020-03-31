rule Trojan_Backdoor_Win32_PhpShell_ice_879_147
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.ice"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "6560b436d3d3bb75e2ef3f032151d139"
        comment = "None"
        date = "2018-11-20"
        description = "Web Shell - file ice.asp"
	strings:
		$s0 = "<%eval request(\"ice\")%>" fullword
	condition:
		all of them
}