rule Trojan_Backdoor_Win32_Sofacy_dropper_533_211
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sofacy.dropper"
        threattype = "Backdoor"
        family = "Sofacy"
        hacker = "None"
        author = "mqx"
        refer = "36524c90ca1fac2102e7653dfadb31b2"
        comment = "None"
        date = "2018-08-08"
        description = "None"
    strings:
        $createdll = {56 8D 4D E8 51 50 FF 15 1C 40 41 00 83 7F 24 54 53 0F 85 C1 00 00 00 6A 06 6A 02 53 6A 02 6A 04 FF 77 10 FF D0}
        $rundll32 = {68 34 97 41 00 57 FF D6 FF 73 10 57 FF D6 FF 74 24 14 57 FF D6 FF 73 20 8B 74 24 1C 33 C0 50 57 FF 74 24 1C 56 50 FF 15 50 41 41 00}
        $setreg = {66 89 55 86 66 89 4D 94 66 89 4D 96 C7 45 B8 52 65 67 53 66 C7 45 BC 65 74 C6 45 BE 56 88 55 BF 88 4D C0 C7 45 C1 75 65 45 78 66 C7 45 C5 57 00 FF 15 34 40 41 00 8D 4D B8 51 50 FF 15 1C 40 41 00 8B D0 33 FF 8B C3 8D 70 02 66 8B 08 83 C0 02 66 3B CF 75 F5 2B C6 8B 75 EC D1 F8 8D 04 45 02 00 00 00 50 53 6A 01 33 C0 50 56 FF 75 E8 FF D2}
    condition:
        all of them
}
            