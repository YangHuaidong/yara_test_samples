rule Trojan_HACKTOOL_Win32_BluesPortScan_v1_832_413 
{
	meta:
        judge = "black"
        threatname = "Trojan[HACKTOOL]/Win32.BluesPortScan.v1"
        threattype = "HACKTOOL"
        family = "BluesPortScan"
        hacker = "None"
        author = "yarGen Yara Rule Generator by Florian Roth - lz"
        refer = "6292f5fc737511f91af5e35643fc9eef"
        comment = "None"
        date = "2018-07-30"
		description = "Auto-generated rule on file BluesPortScan.exe"

	strings:
		$s0 = "This program was made by Volker Voss"
		$s1 = "JiBOo~SSB"
	condition:
		all of them
}