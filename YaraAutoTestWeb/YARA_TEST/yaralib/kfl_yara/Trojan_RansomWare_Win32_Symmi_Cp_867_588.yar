rule Trojan_RansomWare_Win32_Symmi_Cp_867_588
{
    meta:
        judge = "black"
        threatname = "Trojan[RansomWare]/Win32.Symmi.Cp"
        threattype = "RansomWare"
        family = "Symmi"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "16b596de4c0e4d2acdfdd6632c80c070,2afaa709ef5260184cbda8b521b076e1,e3dd1dc82ddcfaf410372ae7e6b2f658"
        comment = "Table 2 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
        date = "2018-11-05"
        description = "Dexter Malware - StarDust Variant "
strings:
	$s1 = "ceh_3\\.\\ceh_4\\..\\ceh_6"
	$s2 = "Yatoed3fe3rex23030am39497403"
	$s3 = "Poo7lo276670173quai16568unto1828Oleo9eds96006nosysump7hove19"
	$s4 = "CommonFile.exe"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}