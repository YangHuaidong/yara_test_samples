rule Trojan_DDoS_Win32_Nitol_B_20180622100933_932 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Win32.Nitol_B"
		threattype = "DDOS"
		family = "Nitol_B"
		hacker = "None"
		refer = "d628c8943dee65f6a8068858d61676c8"
		description = "None"
		comment = "None"
		author = "lizhenling"
		date = "2018-06-21"
	strings:
		$s0 = "ProductName"
		$s1 = "%c%c%c%c%c.exe"
		$s2 = "Description"
		$s3 = "Content-Type: text/html"
		$s4 = "URLDownloadToFileA"
		$s5 = "Accept: text/html, */*"

	condition:
		all of them
}
