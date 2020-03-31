rule Trojan_Ransomware_Win32_Satan_mpress_769_587
{
    meta:
        judge = "black"
        threatname = "Trojan[Ransomware]/Win32.Satan.mpress"
        threattype = "Ransomware"
        family = "Satan"
        hacker = "None"
        author = "mqx"
        refer = "eba5cfb1947e6b336c638be56bd7eda2"
        comment = "None"
        date = "2018-10-16"
        description = "None"
    
    strings:
        $signature = "MPRESS"
        $decode = {2B C0 AC 8B C8 80 E1 F0 24 0F C1 E1 0C 8A E8 AC 0B C8 51 02 CD BD 00 FD FF FF D3 E5 59 58 8B DC 8D A4 6C 90 F1 FF FF 51 2B C9 51 51 8B CC 51 66 8B 17 C1 E2 0C 52 57 83 C1 04 51 50 83 C1 04 56 51 E8 5E 00 00 00 8B E3 5E 5A 2B C0 89 04 32 B4 10 2B D0}
        $ciphertext = {09 34 0A 02 E5 4D 63 20 60 D0 4A 31 82 62 6A 5C D1 5E BA 52 6B F2 F6 3F  FF D1 7B EE 43 C2 52 35 73 98 05 B3 31 E6 24 03 CF B0 2F 5C 39 08 35 7E A8 B4 18 6B DD 59 DA C4  D0 7D E8 53 16 0E 50 1E D9 10 B8 E1 B5 48 43 5F  6B E0 EB CB AB 1C 0E 83}
        $ciphertext2 = {23 BD 75 72 FA 12 4F 9A E7 8D F3 40 B9 5B 56 7B 62 DD 16 FE D4 6E 47 E7 DD 65 4A 81 E1 48 13 8E 3F EF EA D5 CC 03 81 4F 57 D3 EB 28 5A 1F 22 74}
    condition:
        all of them
}