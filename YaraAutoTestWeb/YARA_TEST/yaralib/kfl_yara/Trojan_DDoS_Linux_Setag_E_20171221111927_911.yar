rule Trojan_DDoS_Linux_Setag_E_20171221111927_911 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Setag.E"
		threattype = "DDOS"
		family = "Setag"
		hacker = "None"
		refer = "392874332e9f443873cc542d5c1fa3da,a9e72d8cd9adaeb971626b7357530488,d26b6ffee5d75b3c63c2e080f4bc735f,fb32d9ed9ec428e273d020411369c13a,cfb278a75e92c8c97b0cb25b7a2b698a,c836456f56007f0eb68cfc0907a91b36,b83d3f7f759d79bca810e7fdfd7fbcdf,eff867e3dd8756690f768728be5a9147,c695d26b648251e130c57dce34e330da"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-08-19"
	strings:
		$s0 = "172.16.0.0"
		$s1 = "192.168.0.0"
		$s2 = "%16s 0x%d 0x%d %20s %s"
		$s3 = "chmod 0755 %s"
		$s4 = "mkdir -p %s"
		$s5 = "cp -f %s %s"
		$s6 = "cpu %llu %llu %llu %llu"
		$s7 = "%7s %llu %lu %lu %lu %lu %lu %lu %lu %llu %lu %lu %lu %lu %lu %lu %lu"
		$s8 = "%5s %8x %8x %s"

	condition:
		all of them
}
