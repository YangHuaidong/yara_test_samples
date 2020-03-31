rule Trojan_Linux_Xor_Ex_20161213095208_1065_566 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Xor.Ex"
		threattype = "DDOS"
		family = "Xor"
		hacker = "None"
		refer = "A609138F0791CE100BD2AD8EFA1F74B2,B6E04D4EEA2D4E044B9B5C3DDE3BCE0D,D6A5D9BD5E6842BB595B18A9131A84A8"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2016-10-25"
	strings:
		$s0 = "/etc/init.d/%s"
		$s1 = "d.d/S90%s"
		$s2 = "/proc/%d"
		$s3 = "/proc/net/tcp"
		$s4 = "%d--%s_%d:%s|"
		$s5 = "MemFree: %ld kB"
		$s6 = "MemTotal: %ld kB"
		$s7 = "%a %b %e %H:%M:%S"

	condition:
		5 of them
}
