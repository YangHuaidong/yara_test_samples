rule Trojan_RAT_Win32_Havex_OPC_1056
{
    meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.Memdump"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "8065674de8d79d1c0e7b3baf81246e7d"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "Rule for identifying OPC version of HAVEX"
    strings:
        $mzhdr = "MZ"
        $dll = "7CFC52CD3F87.dll"
        $a1 = "Start finging of LAN hosts..." wide
        $a2 = "Finding was fault. Unexpective error" wide
        $a3 = "Was found %i hosts in LAN:" wide
        $a4 = "Hosts was't found." wide
        $a5 = "Start finging of OPC Servers..." wide
        $a6 = "Was found %i OPC Servers." wide
        $a7 = "OPC Servers not found. Programm finished" wide
        $a8 = "%s[%s]!!!EXEPTION %i!!!" wide
        $a9 = "Start finging of OPC Tags..." wide
    condition:
        $mzhdr at 0 and ($dll or (any of ($a*)))
}