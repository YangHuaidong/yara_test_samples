import "pe"

rule Trojan_Backdoor_Win32_Soeda_Bdha_535_209
{

    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Soeda.Bdha"
        threattype = "Backdoor"
        family = "Soeda"
        hacker = "None"
        author = "@patrickrolsen-mqx"
        refer = "869fa4dfdbabfabe87d334f85ddda234"
        comment = "None"
        date = "2018-07-26"
        description = "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"

    strings:
        $magic = { 4d 5a } // MZ
        $string1 = "www.micro1.zyns.com"
        $string2 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)"
        $string3 = "msacm32.drv" wide
        $string4 = "C:\\Windows\\Explorer.exe" wide
        $string5 = "Elevation:Administrator!" wide
        $string6 = "C:\\Users\\cmd\\Desktop\\msacm32\\Release\\msacm32.pdb"

    condition:
        $magic at 0 and 4 of ($string*)
}
