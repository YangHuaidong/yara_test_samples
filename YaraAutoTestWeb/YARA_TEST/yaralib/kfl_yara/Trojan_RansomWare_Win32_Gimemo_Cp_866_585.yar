rule Trojan_RansomWare_Win32_Gimemo_Cp_866_585
{
    meta:
        judge = "black"
        threatname = "Trojan[RansomWare]/Win32.Gimemo.Cp"
        threattype = "RansomWare"
        family = "Gimemo"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "759154d20849a25315c4970fe37eac59"
        comment = "Table 2 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
        date = "2018-11-05"
        description = "Project Hook"
strings:
	$s1 = "CallImage.exe"
	$s2 = "BurpSwim"
	$s3 = "Work\\Project\\Load"
	$s4 = "WortHisnal"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}