rule Trojan_Backdoor_Win32_GenericKD_cjjbawl_574_92
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.GenericKD.cjjbawl"
        threattype = "backdoor"
        family = "GenericKD"
        hacker = "None"
        author = "balala"
        refer = "ac50d9ac014d10370ff85269e0c878ac"
        comment = "None"
        date = "2018-08-14"
        description = "None"
    strings:
		$s1 = "360sd.exe" nocase wide ascii
		$s2 = "QQPCRTP.exe" nocase wide ascii
		$s6 = "zaqwsxcde12333" nocase wide ascii
		$s8 = "adfcxvxcvx" nocase wide ascii
    condition:
        all of them
}