rule Trojan_RAT_Win32_Havex_Fertger_1054
{
    meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.Fertger"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "ba8da708b8784afd36c44bb5f1f436bc"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "Rule for identifying Fertger version of HAVEX"
    strings:
        $mz = "MZ"
        $a1="\\\\.\\pipe\\mypipe-f" wide
        $a2="\\\\.\\pipe\\mypipe-h" wide
        $a3="\\qln.dbx" wide
        $a4="*.yls" wide
        $a5="\\*.xmd" wide
        $a6="fertger" wide
        $a7="havex"
    condition:
        $mz at 0 and 3 of ($a*) 
}