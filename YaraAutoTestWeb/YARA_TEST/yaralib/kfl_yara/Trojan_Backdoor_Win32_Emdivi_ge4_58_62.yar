rule Trojan_Backdoor_Win32_Emdivi_ge4_58_62
 {

    meta:

        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Emdivi.ge4"
		threattype = "Backdoor"
		family = "Emdivi"
		hacker = "None"
		comment = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		author = "Florian Roth @Cyber0ps--DC"
		description = "Detects Emdivi Malware Emdivi_Gen4" 
		refer = "302fbe13736403921ad7f9d310d7beb2"
		super_rule = 1
        score = 80
        hash1 = "302fbe13736403921ad7f9d310d7beb2"
        hash2 = "bf7bc4c288df36bdc4f01e3d97cffc10"
        hash3 = "337efc3851244c93fc0d812fb4ae66f9"
        hash4 = "b8d7fec363ac1d303717ba0732c7eb40"
        hash5 = "62cef94f307b1d2409c7836d75a96b4c"
        hash6 = "07aa0340ec0bfbb2e59f1cc50382c055"
  
    strings:
        $s1 = ".http_port\", " fullword wide
        $s2 = "UserAgent: " fullword ascii
        $s3 = "AUTH FAILED" fullword ascii
        $s4 = "INVALID FILE PATH" fullword ascii
        $s5 = ".autoconfig_url\", \"" fullword wide
        $s6 = "FAILED TO WRITE FILE" fullword ascii
        $s7 = ".proxy" fullword wide
        $s8 = "AuthType: " fullword ascii
        $s9 = ".no_proxies_on\", \"" fullword wide
  
    condition:
        uint16(0) == 0x5a4d and filesize < 853KB and all of them
}