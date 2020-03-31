rule Worm_Ransomware_Win32_WannaCry_d_1129
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.d"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "7f7ccaa16fb15eb1c7399d422f8363e8"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "http://www.elmundo.es/tecnologia/2017/05/12/59158a8ce5fdea194f8b4616.html"
	strings:		
		$a = "RegCreateKeyW" wide ascii nocase
		$b = "cmd.exe /c"
		$c = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
		$d = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii
		$e = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii
		$f = "tasksche.exe"
	condition:
		uint16(0) == 0x5A4D and $a and for all of ($b, $c, $d, $e, $f) : (@ > @a)
}