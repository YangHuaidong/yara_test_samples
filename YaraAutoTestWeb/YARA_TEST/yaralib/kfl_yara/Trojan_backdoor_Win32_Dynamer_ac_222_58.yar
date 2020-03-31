import "pe"
rule Trojan_backdoor_Win32_Dynamer_ac_222_58 
{

    meta:
        judge = "black"
        threatname = "Trojan[backdoor]/Win32.Dynamer.ac"
        threattype = "backdoor"
        family = "Dynamer"
        hacker = "None"
        author = "Florian Roth-mqx"
        refer = "2ea30517938dda8a084aa00e5ee921f6"
        comment = "None"
        date = "2018-07-19"
        description = "PassCV Malware mentioned in Cylance Report"

    strings:
        $s1 = "WOODTALE TECHNOLOGY INC" ascii
        $s2 = "Flyingbird Technology Limited" ascii
        $s3 = "Neoact Co., Ltd." ascii
        $s4 = "AmazGame Age Internet Technology Co., Ltd" ascii
        $s5 = "EMG Technology Limited" ascii
        $s6 = "Zemi Interactive Co., Ltd" ascii
        $s7 = "337 Technology Limited" ascii
        $s8 = "Runewaker Entertainment0" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them )
}