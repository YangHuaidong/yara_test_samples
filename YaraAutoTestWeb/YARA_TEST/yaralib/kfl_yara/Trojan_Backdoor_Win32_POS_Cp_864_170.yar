rule Trojan_Backdoor_Win32_POS_Cp_864_170
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.POS.Cp"
        threattype = "Backdoor"
        family = "POS"
        hacker = "None"
        author = "copy"
        refer = "ce0296e2d77ec3bb112e270fc260f274"
        comment = "Table 2 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
        date = "2018-11-05"
        description = "Point of Sale (POS) Malware"
strings:
	$s1 = "\\system32\\winxml.dll"
	//$s2 = "cmd /c net start %s"
	//$s3 = "=== pid:"
	//$s4 = "GOTIT"
	//$s5 = ".memdump"
	//$s6 = "POSWDS"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}