rule Trojan_RAT_Win32_AlienSpy_javaw_20161213095213_1071_595 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.AlienSpy.javaw"
		threattype = "rat"
		family = "AlienSpy"
		hacker = "None"
		refer = "cfce426555749d6733dcac8c5342aba4"
		description = "Compile by java,http://www.zdnet.com/article/alienspy-rat-strikes-over-400000-victims-worldwide/"
		comment = "None"
		author = "djw, Kevin Breen <kevin@techanarchy.net>"
		date = "2015-03-01"
	strings:
		$a1 = "Main.classPK"
		$a2 = "MANIFEST.MFPK"
		$a3 = "plugins/Server.classPK"
		$a4 = "META-INF/MANIFEST.MF"
		$a5 = "ID"
		$b1 = "config.xml"
		$b2 = "options/PK"
		$b3 = "plugins/PK"
		$b4 = "util/PK"
		$b5 = "util/OSHelper/PK"
		$b6 = "Start.class"
		$b7 = "AlienSpy"

	condition:
		all of ($a*) or all of ($b*)
}
