rule Trojan_Downloader_Win32_Agent_yh_68_344 
{

    meta:
        judge = "black"
				threatname = "Trojan[Downloader]/Win32.Agent.yh"
				threattype = "Downloader"
				family = "Agent"
				hacker = "None"
				comment = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
				date = "2016-01-03"
				author = "Florian Roth--DC"
				description = "Detects VBS Agent from BlackEnergy Report - file Dropbearrun.vbs " 
				refer = "0af5b1e8eaf5ee4bd05227bf53050770"
        
    strings:
        $s0 = "WshShell.Run \"dropbear.exe -r rsa -d dss -a -p 6789\", 0, false" fullword ascii
        $s1 = "WshShell.CurrentDirectory = \"C:\\WINDOWS\\TEMP\\Dropbear\\\"" fullword ascii
        $s2 = "Set WshShell = CreateObject(\"WScript.Shell\")" fullword ascii /* Goodware String - occured 1 times */
   
    condition:
        filesize < 1KB and 2 of them
}


