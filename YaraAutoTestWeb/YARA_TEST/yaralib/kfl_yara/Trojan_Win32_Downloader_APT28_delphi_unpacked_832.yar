rule Trojan_Downloader_Win32_APT28_delphi_unpacked_832
{

    meta:
        judge = "black"
		threatname = "Trojan[Downloader]/Win32.APT28.delphi_unpacked"
		threattype = "Downloader"
		family = "APT28"
		hacker = "APT28"
		comment = "None"
		date = "2018-11-27"
		author = "mqx"
		description = "APT28 Zebrocy stage 1 delphi downloader unpacked" 
		refer = "7f7e7329d5628d2c1a0cb9ec370a2144"
    strings:
        $str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $hardcode1 = "636D642E657865202F6320"
        $hardcode2 = "476F6F676C65557064617465537276"
        $hardcode3 = "4669786564"
        $hardcode4 = "52656D6F7465"
        $hardcode5 = "6364726F6D"
        $hardcode6 = "53595354454D494E464F2026205441534B4C495354"
        $hardcode7 = "4D6963726F736F667420576F7264"
        $hardcode8 = "2E2E2E5C"
        $hardcode9 = "706F6C3D"
        $hardcode10 = "4D6F7A696C6C612076352E31202857696E646F7773204E5420362E313B2072763"
        $hardcode11 = "6472766D6D632E657865"
        $hardcode12 = "687474703A2F2F38362E3130362E3133312E3137372F537570706F72744139316"
    condition:
        all of them
}