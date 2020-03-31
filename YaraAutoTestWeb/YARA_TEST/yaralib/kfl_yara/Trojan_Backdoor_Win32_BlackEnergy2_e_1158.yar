rule Trojan_Backdoor_Win32_BlackEnergy2_e_1158
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BlackEnergy2.e"
		threattype = "ICS,Backdoor"
		family = "BlackEnergy2"
		hacker = "None"
		refer = "298b9a6b1093e037e65da31f9ac1a807"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-19"
		description = "None"
    strings:
        $s0 = {49 6F 52 65 6D 6F 76 65 53 68 61 72 65 41 63 63 65 73 73} //IoRemoveShareAccess
        $s1 = {49 6F 44 65 6C 65 74 65 44 65 76 69 63 65} //IoDeleteDevice
        $s2 = {52 74 6C 44 65 6C 65 74 65} //RtlDelete
		$s3 = {45 78 44 65 6C 65 74 65 52 65 73 6F 75 72 63 65 4C 69 74 65} //ExDeleteResourceLite
		$s4 = {49 6F 52 65 6C 65 61 73 65 56 70 62 53 70 69 6E 4C 6F 63 6B 00 00 1E 01 49 6F 41 63 71 75 69 72 65 56 70 62 53 70 69 6E 4C 6F 63 6B} //IoReleaseVpbSpinLock....IoAcquireVpbSpinLock
    condition:
        all of them
}