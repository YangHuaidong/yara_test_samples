rule Trojan_Backdoor_Win32_Lecna_dha_63_128
{

    meta:
        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Lecna.G!dha"
		threattype = "Backdoor"
		family = "Lecna"
		hacker = "None"
		comment = "https://goo.gl/ZiJyQv"
		date = "2015-05-14"
		author = "Florian Roth--DC"
		description = "Detects APT backspace" 
		refer = "8bfba8ebd2f79fc21844e1f6175475be"
				        
    strings:
        $s1 = "!! Use Splice Socket !!"
        $s2 = "User-Agent: SJZJ (compatible; MSIE 6.0; Win32)"
        $s3 = "g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d"

    condition:
        uint16(0) == 0x5a4d and all of them
}