rule Trojan_Backdoor_Win32_Emdivi_g_57_63
{

    meta:
        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Emdivi.g"
		threattype = "Backdoor"
		family = "Emdivi"
		hacker = "None"
		comment = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		author = "Florian Roth @Cyber0ps--DC"
		description = "Detects Emdivi Malware" 
		refer = "302fbe13736403921ad7f9d310d7beb2"
		super_rule = 1
        score = 80
        hash1 = "302fbe13736403921ad7f9d310d7beb2"
        hash2 = "07aa0340ec0bfbb2e59f1cc50382c055"
  
    strings:
        $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727.42)" fullword ascii
        $s2 = "\\Mozilla\\Firefox\\Profiles\\" fullword ascii
        $s4 = "\\auto.cfg" fullword ascii
        $s5 = "/ncsi.txt" fullword ascii
        $s6 = "/en-us/default.aspx" fullword ascii
        $s7 = "cmd /c" fullword ascii
        $s9 = "APPDATA" fullword ascii /* Goodware String - occured 25 times */
   
    condition:
        uint16(0) == 0x5a4d and filesize < 850KB and (( $x1 and 1 of ($s*)) or ( 4 of ($s*)))
}
