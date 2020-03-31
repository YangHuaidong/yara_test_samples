rule Trojan_Linux_Dofloo_20161213095159_1049_551 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Dofloo"
		threattype = "DDOS"
		family = "Dofloo"
		hacker = "none"
		refer = "0c7ce0ae478e99274a9bee19252bbed9"
		description = "none"
		comment = "none"
		author = "HuangYY"
		date = "2016-08-17"
	strings:
		$s0 = "/usr/include/bits"
		$s1 = "/usr/include/sys"
		$s2 = "sed -i -e '2 i%s/%s' /etc/rc.local"
		$s3 = "%a %b %e %H:%M:%S %Z %Y"
		$s4 = "MemFree: %ld kB"
		$s5 = "M%hu.%hu.%hu%n"

	condition:
		all of them
}
