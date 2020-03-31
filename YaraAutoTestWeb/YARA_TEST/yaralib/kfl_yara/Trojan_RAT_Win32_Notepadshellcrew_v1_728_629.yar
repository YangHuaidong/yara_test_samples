rule Trojan_RAT_Win32_Notepadshellcrew_v1_728_629
{
        meta:
            judge = "black"
            threatname = "Trojan[RAT]/Win32.Notepadshellcrew.v1"
            threattype = "RAT"
            family = "Notepadshellcrew"
            hacker = "None"
            author = "RSA_IR - lz"
            refer = "106E63DBDA3A76BEEB53A8BBD8F98927"
            comment = "None"
            date = "2013-06-04"
            description = "notepad.exe v 1.1"

        strings:
                $s1 = "75BAA77C842BE168B0F66C42C7885997"
                $s2 = "B523F63566F407F3834BCC54AAA32524"
        condition:
                $s1 or $s2
}