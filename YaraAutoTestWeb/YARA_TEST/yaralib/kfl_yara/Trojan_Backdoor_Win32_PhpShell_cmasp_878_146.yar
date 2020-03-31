rule Trojan_Backdoor_Win32_PhpShell_cmasp_878_146
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.cmasp"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "895ca846858c315a3ff8daa7c55b3119"
        comment = "None"
        date = "2018-11-20"
        description = "Web Shell - file cmd.asp"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
		$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
		$s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
	condition:
		1 of them
}