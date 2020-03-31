rule Trojan_Backdoor_Win32_Sofacy_ct_532_210
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sofacy.ct"
        threattype = "Backdoor"
        family = "Sofacy"
        hacker = "None"
        author = "mqx"
        refer = "aa2cd9d9fc5d196caa6f8fd5979e3f14"
        comment = "None"
        date = "2018-08-08"
        description = "None"

    strings:
        $decrypt = {8D 0C 30 C7 45 FC 0A 00 00 00 33 D2 F7 75 FC 8A 82 B8 71 00 10 32 04 0F 88 01 8B 45 0C 40 89 45 0C 3B C3}     
        $verification1 = {81 7E 04 CD AB 34 12 0F 85 9C 00 00 00}    
        $verification2 = {81 7E 04 34 12 76 98 89 7D 08 74 2E}    
        $decryptC2 = {C7 03 02 00 00 00 E8 58 D3 FF FF 59 89 47 0C 39 33 76 26 B8 A0 73 00 10 89 45 FC 6A 2C 50 E8 B8 DA FF FF}
        $proxy = {66 89 45 AA 8D 85 78 FF FF FF 50 8D 45 F0 66 89 4D 94 50 8D 45 E0 66 89 55 96 50 53 8D 45 94 66 89 4D 9A 50 56 66 89 55 9C 66 89 4D A0 66 89 55 A2 66 89 4D A6 66 89 55 A8 FF 15 00 71 00 10}
        $inject = {89 75 EC 89 7D E8 E8 39 0D 00 00 8B D8 59 85 DB 0F 84 C6 00 00 00 8D 45 F8 89 7D F8 50 53 E8 56 F5 FF FF}
        $sendRequest = {53 53 85 C0 8B D3 50 0F 45 D7 52 FF 76 04 FF 15 30 71 00 10 53 53 57 53 53 68 BB 01 00 00 FF 76 08 89 45 E4 50 FF 15 3C 71 00 10 8B CE 89 45 F0 E8 D4 05 00 00 6A 04 68 08 75 00 10 8B F8 E8 B4 E6 FF FF 59 59 53 68 00 00 80 00 53 53 53 57 8B F0 56 FF 75 F0 FF 15 28 71 00 10 8D 4D EC 89 45 F8 51 8D 4D FC C7 45 EC 04 00 00 00 51 6A 1F 50 FF 15 20 71 00 10 81 4D FC 80 31 00 00 8D 45 FC 6A 04 50 6A 1F FF 75 F8 FF 15 1C 71 00 10 56 E8 2E F6 FF FF 57 E8 28 F6 FF FF FF 75 0C E8 AB E2 FF FF 8B 75 F8 83 C4 0C 50 FF 75 0C 53 53 56 FF 15 34 71 00 10 }    
        $cmd = {51 50 8D 04 37 50 FF 75 F0 FF 15 24 71 00 10 03 7D FC 83 7D FC 00 8B 45 08 74 04 3B F8 72 DE 6A 00 3B F8 8B 7D F8 5E 75 0F FF 75 0C 50 57 E8 77 DE FF FF}

    condition:
        all of them
}