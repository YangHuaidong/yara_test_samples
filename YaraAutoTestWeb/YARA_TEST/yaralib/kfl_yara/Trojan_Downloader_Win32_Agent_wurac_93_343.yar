rule Trojan_Downloader_Win32_Agent_wurac_93_343
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.Agent.wurac"
        threattype = "Downloader"
        family = "Agent"
        hacker = "None"
        author = "dc"
        refer = "2C65085E7C71FA2C02C9B65E9B747E5B"
        comment = "None"
        date = "2018-04-29"
        description = "This rule detects a dns tunnel tool used in Operation Iron Tiger Cyber Safety Solutions, Trend Micro  IronTiger_dnstunnel"
    strings:
        $mz="MZ"
        $str1="\\DnsTunClient\\" nocase wide ascii
        $str2="\\t-DNSTunnel\\" nocase wide ascii
        $str3="xssok.blogspot" nocase wide ascii
        $str4="dnstunclient" nocase wide ascii
        $mistake1="because of error, can not analysis" nocase wide ascii
        $mistake2="can not deal witn the error" nocase wide ascii
        $mistake3="the other retun one RST" nocase wide ascii
        $mistake4="Coversation produce one error" nocase wide ascii
        $mistake5="Program try to use the have deleted the buffer" nocase wide ascii
    condition:
        ($mz at 0) and ((any of ($str*)) or (any of ($mistake*)))
}
