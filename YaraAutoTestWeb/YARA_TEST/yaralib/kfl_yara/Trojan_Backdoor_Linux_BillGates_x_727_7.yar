rule Trojan_Backdoor_Linux_BillGates_x_727_7
{

    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.BillGates.x"
        threattype = "Backdoor"
        family = "BillGates"
        hacker = "None"
        author = "mqx"
        refer = "ace2183145989cd4e22511210a04bc99"
        comment = "None"
        date = "2018-09-26"
        description = "BillGates Trojan"
    
    strings:
        $str1 = "11CUpdateBill"
        $str2 = "12CUpdateGates"
        $str3 = "/home/monitor/Gates"
        $encode = "31231C53A1BF43BC6EF2D6D97F9267496789D04C4BDBA213B0C04CE5C5267E8D8"
        $str5 = "keld@dkuug.dk"
        $str6 = "/usr/bin/oracle"
    
    condition:
        all of them
}