rule Trojan_DDoS_Win32_ServStart_x_695
{
    meta:
	    judge = "black"
		threatname = "Trojan[DDoS]/Win32.ServStart.x"
		threattype = "DDoS"
		family = "ServStart"
		hacker = "None"
		refer = "299522fe80c136bdaca59c58b5a2d4e9"
		author = "xc"
		comment = "None"
		date = "2017-09-14"
		description = "None"
	strings:
	    $s0 = "110.510w.cn:8080"
		$s1 = "WaveDoc.cpp"
		$s2 = "WaveView.cpp"
		$s3 = "Cache.dat"
	condition:
	    all of them		
}