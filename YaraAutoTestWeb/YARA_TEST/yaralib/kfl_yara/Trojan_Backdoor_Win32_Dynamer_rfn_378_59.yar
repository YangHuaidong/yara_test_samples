rule Trojan_Backdoor_Win32_Dynamer_rfn_378_59 {

    meta:
        judge = "black"
        threatname = "Trojan[backdoor]/Win32.Dynamer.rfn"
        threattype = "backdoor"
        family = "Dynamer"
        hacker = "None"
        author = "mqx"
        refer = "8F4FC2E10B6EC15A01E0AF24529040DD"
        comment = "None"
        date = "2018-07-02"
        description = "HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure"

    strings:

        $rsaKey = {7B 4E 1E A7 E9 3F 36 4C DE F4 F0 99 C4 D9 B7 94 A1 FF F2 97 D3 91 13 9D C0 12 02 E4 4C BB 6C 77 48 EE 6F 4B 9B 53 60 98 45 A5 28 65 8A 0B F8 39 73 D7 1A 44 13 B3 6A BB 61 44 AF 31 47 E7 87 C2 AE 7A A7 2C 3A D9 5C 2E 42 1A A6 78 FE 2C AD ED 39 3F FA D0 AD 3D D9 C5 3D 28 EF 3D 67 B1 E0 68 3F 58 A0 19 27 CC 27 C9 E8 D8 1E 7E EE 91 DD 13 B3 47 EF 57 1A CA FF 9A 60 E0 64 08 AA E2 92 D0}

    condition: 
        any of them
}