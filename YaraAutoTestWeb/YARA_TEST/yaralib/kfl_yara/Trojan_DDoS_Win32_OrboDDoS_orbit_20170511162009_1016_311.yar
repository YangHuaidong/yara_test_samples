rule Trojan_DDoS_Win32_OrboDDoS_orbit_20170511162009_1016_311 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.OrboDDoS.orbit"
		threattype = "DDOS"
		family = "OrboDDoS"
		hacker = "None"
		refer = "49055a8ffade6718ea6c917779761c0d,5196b963e368d084b89e800e8d192741,eb681d15b0b054ff7fe50dacf41d070c,14be01db34df696adfb263805437fa60"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-05-04"
	strings:
		$s0 = "orbitdownloader" nocase
		$s1 = "orbitdm.exe" nocase
		$s2 = "orbit" nocase

	condition:
		2 of them
}
