rule Trojan_Backdoor_Win32_Liudoor_dsmbndqx_679_130
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Liudoor.dsmbndqx"
        threattype = "Backdoor"
        family = "Liudoor"
        hacker = "None"
        author = "balala"
        refer = "78b56bc3edbee3a425c96738760ee406,5aa0510f6f1b0e48f0303b9a4bfc641e,531d30c8ee27d62e6fbe855299d0e7de,2be2ac65fd97ccc97027184f0310f2f3,6093505c7f7ec25b1934d3657649ef07"
        comment = "None"
        date = "2018-09-06"
        description = "None"
	strings:
        $string0 = "Succ"
        $string1 = "Fail"
        $string2 = "pass"
        $string3 = "exit"
        $string4 = "svchostdllserver.dll"
        $string5 = "L$,PQR"
        $string6 = "0/0B0H0Q0W0k0"
        $string7 = "QSUVWh"
        $string8 = "Ht Hu["
    condition:
        all of them
}