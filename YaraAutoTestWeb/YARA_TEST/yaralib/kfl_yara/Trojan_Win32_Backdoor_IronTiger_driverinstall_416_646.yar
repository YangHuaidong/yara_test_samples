rule Trojan_Win32_Backdoor_IronTiger_driverinstall_416_646
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.IronTiger.driverinstall"
        threattype = "Backdoor"
        family = "IronTiger"
        hacker = "None"
        author = "mqx"
	    refer="983EAA00360F85CF84E7D5954B9C3E70"
        comment = "None"
        date = "2018-04-27"
        description = "None"

    strings:
        $mz="MZ"
        $str1="openmydoor" nocase wide ascii
        $str2="Install service error" nocase wide ascii
        $str3="start remove service" nocase wide ascii
        $str4="NdisVersion" nocase wide ascii
    condition:
        $mz at 0 and (2 of ($str*))
}
