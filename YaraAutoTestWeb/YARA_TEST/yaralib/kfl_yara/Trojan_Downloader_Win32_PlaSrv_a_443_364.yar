rule Trojan_Downloader_Win32_PlaSrv_a_443_364
{

meta:
    judge = "black"
		threatname = "Trojan[Downloader]/Win32.PlaSrv.a"
		threattype = "Downloader"
		family = "PlaSrv"
		hacker = "None"
		comment = "None"
		date = "2016-04-12"
		author = "Microsoft-DC"
		description = "Hotpatching Injector" 
		refer = "ff7f949da665ba8ce9fb01da357b5141"
		original_sample_sha1 = "ff7f949da665ba8ce9fb01da357b51415634eaad"
    unpacked_sample_sha1 = "dff2fee984ba9f5a8f5d97582c83fca4fa1fe131"

strings:
    $Section_name = ".hotp1"
    $offset_x59 = { C7 80 64 01 00 00 00 00 01 00 }

condition:
    $Section_name and $offset_x59
}