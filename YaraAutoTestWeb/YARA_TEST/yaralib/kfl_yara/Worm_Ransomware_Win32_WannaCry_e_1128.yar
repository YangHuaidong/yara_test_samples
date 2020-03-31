rule Worm_Ransomware_Win32_WannaCry_e_1128
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.e"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "4da1f312a214c07143abeeafb695d904"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "None"
	strings:		
        $s0 = {410044004D0049004E0024}
        $s1 = "WannaDecryptor"
        $s2 = "WANNACRY"
        $s3 = "Microsoft Enhanced RSA and AES Cryptographic"
        $s4 = "PKS"
        $s5 = "StartTask"
        $s6 = "wcry@123"
        $s7 = {2F6600002F72}
        $s8 = "unzip 0.15 Copyrigh"
        $s9 = "Global\\WINDOWS_TASKOSHT_MUTEX"        
        $s10 = "Global\\WINDOWS_TASKCST_MUTEX"   
        $s11 = {7461736B736368652E657865000000005461736B5374617274000000742E776E7279000069636163}
        $s12 = {6C73202E202F6772616E742045766572796F6E653A46202F54202F43202F5100617474726962202B68}
        $s13 = "WNcry@2ol7"
        $s14 = "wcry@123"
        $s15 = "Global\\MsWinZonesCacheCounterMutexA"
	condition:
		$s0 and $s1 and $s2 and $s3 or $s4 and $s5 and $s6 and $s7 or $s8 and $s9 and $s10 or $s11 and $s12 or $s13 or $s14 or $s15
}