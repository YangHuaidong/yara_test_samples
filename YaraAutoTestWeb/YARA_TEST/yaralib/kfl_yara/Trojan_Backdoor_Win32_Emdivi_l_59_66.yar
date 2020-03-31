rule Trojan_Backdoor_Win32_Emdivi_l_59_66
 {

    meta:
        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Emdivi.l"
		threattype = "Backdoor"
		family = "Emdivi"
		hacker = "None"
		comment = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		author = "Florian Roth @Cyber0ps--DC"
		description = "Detects Emdivi malware in SFX Archive  Emdivi_SFX" 
		refer = "76eca4edb4d9035184e335694b1967fe"
		score = 70
		hash1 = "76eca4edb4d9035184e335694b1967fe"
        hash2 = "3b2b36edbf2934c7a872e32c5bfcde2a"
				
    strings:
        $x1 = "Setup=unsecess.exe" fullword ascii
        $x2 = "Setup=leassnp.exe" fullword ascii
        $s1 = "&Enter password for the encrypted file:" fullword wide
        $s2 = ";The comment below contains SFX script commands" fullword ascii
        $s3 = "Path=%temp%" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and filesize < 740KB and (1 of ($x*) and all of ($s*))
}