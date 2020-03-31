rule Trojan_RAT_Win32_Xiclog_A_562_635
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Xiclog.A"
        threattype = "RAT"
        family = "Xiclog"
        hacker = "None"
        author = "mqx"
        refer = "8a8659e53b4d952ff1787df9ed9011ec"
        comment = "None"
        date = "2018-08-10"
        description = "VB compile"
    
    strings:
        $code1 = {1E 02 7B CF 01 00 04 2A 22 02 03 7D CF 01 00 04 2A 00 00 00 1E 02 7B D0 01 00 04 2A 22 02 03 7D D0 01 00 04 2A 00 00 00 1E 02 7B D1 01 00 04 2A 22 02 03 7D D1 01 00 04 2A 00 00 00 1E 02 7B D2 01 00 04 2A 22 02 03 7D D2 01 00 04 2A 00 00 00 1E 02 7B D3 01 00 04 2A 22 02 03 7D D3 01 00 04 2A 00 00 00 1E 02 7B D4 01 00 04 2A 22 02 03 7D D4 01 00 04 2A 00 00 00}
        $code2 = {1E 02 7B E9 01 00 04 2A 22 02 03 7D E9 01 00 04 2A 00 00 00}
        $code3 = {1E 02 7B E0 02 00 04 2A 22 02 03 7D E0 02 00 04 2A 00 00 00 1E 02 7B E1 02 00 04 2A 22 02 03 7D E1 02 00 04 2A 00 00 00 1E 02 7B E2 02 00 04 2A 22 02 03 7D E2 02 00 04 2A 00 00 00 1E 02 7B E3 02 00 04 2A 22 02 03 7D E3 02 00 04 2A 00 00 00 1E 02 7B E4 02 00 04 2A 22 02 03 7D E4 02 00 04 2A 00 00 00 1E 02 7B E5 02 00 04 2A 22 02 03 7D E5 02 00 04 2A 00 00 00 1E 02 7B E6 02 00 04 2A 22 02 03 7D E6 02 00 04 2A 00 00 00}
        $code4 = {1E 02 7B 08 03 00 04 2A 22 02 03 7D 08 03 00 04 2A 00 00 00}
        $str1 = "get_IsConnected"
        $str2 = "get_LocalAddress"
    condition:
        all of them
}