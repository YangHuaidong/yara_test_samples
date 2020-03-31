rule Trojan_Backdoor_Win32_Mysql_a_726_132
{

    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Mysql.a"
        threattype = "Backdoor"
        family = "Mysql"
        hacker = "None"
        author = "mqx"
        refer = "d6362bdf13a789790e7cadcd110b9e4d"
        comment = "None"
        date = "2018-09-25"
        description = "mysql UDF Backdoor"
    
    strings:
        $str1 = "KillProcess"
        $str2 = "ProcessView"
        $str3 = "backshell"
        $str4 = "cmdshell"
        $str5 = "downloader"
        $str6 = "open3389"
        $code1 = {8A 01 88 02 41 42 84 C0 75 F6 6A 00 6A 02 E8 06 0B 00 00 8D 8D C4 FD FF FF 8B F8 51 57 C7 85 C4 FD FF FF 28 01 00 00 E8 E7 0A 00 00}
        $code2 = {51 6A 00 68 3F 00 0F 00 6A 00 68 D5 C4 00 10 6A 00 68 90 C4 00 10 68 02 00 00 80 89 95 EC FE FF FF FF D6 8B 85 F4 FE FF FF 8B 3D 10 C0 00 10 6A 04}
    
    condition:
        all of them
}