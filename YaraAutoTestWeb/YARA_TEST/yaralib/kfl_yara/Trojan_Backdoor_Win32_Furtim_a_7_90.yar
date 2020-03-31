rule Trojan_Backdoor_Win32_Furtim_a_7_90 
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.Furtim.a"
				threattype = "Backdoor"
				family = "Furtim"
				hacker = "None"
				comment = "https://sentinelone.com/blogs/sfg-furtims-parent/   Furtim_Parent_1"
				date = "2016-07-16"
				author = "Florian Roth-DC"
				description = "Detects Furtim Parent Malware" 
				refer = "564ac87ca4114edd6a84a005092f1285"

    strings:
        /* RC4 encryption password */
        $x1 = "dqrChZonUF" fullword ascii
        /* Other strings */
        $s1 = "Egistec" fullword wide
        $s2 = "Copyright (C) 2016" fullword wide
        /* Op Code */
        $op1 = { c0 ea 02 88 55 f8 8a d1 80 e2 03 }
        $op2 = { 5d fe 88 55 f9 8a d0 80 e2 0f c0 }
        $op3 = { c4 0c 8a d9 c0 eb 02 80 e1 03 88 5d f8 8a d8 c0 }
  
    condition:
        ( uint16(0) == 0x5a4d and filesize < 900KB and ( $x1 or ( all of ($s*) and all of ($op*) ) ) ) or all of them
}