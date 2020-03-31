rule Trojan_Downloader_Win32_APT28_AutoIt_831
{

    meta:
        judge = "black"
		threatname = "Trojan[Downloader]/Win32.APT28.AutoIt"
		threattype = "Downloader"
		family = "APT28"
		hacker = "APT28"
		comment = "None"
		date = "2018-11-28"
		author = "mqx"
		description = "APT28 Zebrocy stage 2 delphi downloader" 
		refer = "0b677ddfde0aae43d9554f08542bd0f4"
    strings:
        $hardcode = "6578652E32336C6C646E7572"
        $hardcode2 = "2C2331"
        $hardcode3 = "3F636C69656E743D"
        $hardcode4 = "687474703A2F2F38392E3234392E36352E3136362F696E742D72656C656173652F636865636B2D757365722F7573657269642E706870"
        $str = "SOFTWARE\\Borland\\Delphi\\RTL"
    condition:
        all of them
}