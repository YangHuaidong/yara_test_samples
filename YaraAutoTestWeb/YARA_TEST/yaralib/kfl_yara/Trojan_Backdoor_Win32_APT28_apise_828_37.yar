rule Trojan_Backdoor_Win32_APT28_apise_828_37
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.APT28.apise"
				threattype = "Backdoor"
				family = "APT28"
				hacker = "APT28"
				comment = "None"
				date = "2018-11-14"
				author = "mqx"
				description = "Trump's_Attack_on_Syria_English.docx, backdoor" 
				refer = "35465e7fabb45ff2a7fe19e8539b5e67"
    strings:
        $key = {67 64 21 35 3F 11 30 3A 31 1A 34 76 00 3D 28 54 4D 1F 20 5A 47 7C 16 32 36 56 75 5B 11 6C 58 06 37 22 72 20 5A 47 7C 16 32 36 56 75 5B 11 6C 58 06 37 22 72 21 18 3F 7C 09 3C 6F 56 41 1D 44 3F 24 0F 38 51 59 3B 75 5B 11 6C 58 06 37 22 72 20 5A 47 7C 16 32 36 56 75 5B 11 6C 58 06 37 22 72 78 36 1E 50 6C 58 06 37 22 72 20 5A 47 7C 16 32 36 56 78 32 08 5C 41 10 54 1A 12 4A 20 5A 47 7C 16 32 36 56 78 10 23 70 01 28 6A 52 22 72 20 5A 47 7C 16 32 36 56 78 12 37 7E 0E 39 6A 37 22 72 20 5A 47 7C 16 32 36 56 78 03 35 75 42 3F 72 40 22 72 20 5A 47 7C 16 32 36 56 78 14 2B 61 00 3D 62 58 57 10 4C 3F 47 7C 16 32 36 56 78 03 35 75 42 2F 67 47 0C 05 4D 36 34 1F 64 5B 46 22 78 00 37 61 0A 3D 65 37 22 72 20 5A 47 7C 16 32 36 56 67 41 36 29 08 71 4D 41 63 23 03}
		$str = "apisecconnect.dll"
		$key_mutex = {30 19 0B 56 08 2E 7F 5F 72 0B 4B 22 00 0A 7E 76 79 17 2F 35 44}
    condition:
        all of them
} 