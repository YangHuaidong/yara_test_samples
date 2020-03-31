import "pe"
rule Trojan_Downloader_Win32_gen_h_226_352
{

   meta:
        judge = "suspicious"
        threatname = "Trojan[downloader]/Win32.gen.h"
        threattype = "downloader"
        family = "gen"
        hacker = "None"
        author = "Florian Roth-mqx"
        refer = "e32dc66f1337cb8b1ed4f87a441e9457"
        comment = "None"
        date = "2018-07-19"
        description = "PassCV Malware mentioned in Cylance Report"

   strings:
      $s1 = "QWNjZXB0On" fullword ascii /* base64 encoded string 'Accept:' */
      $s2 = "VXNlci1BZ2VudDogT" fullword ascii /* b64: User-Agent: */
      $s3 = "dGFzay5kbnME3luLmN" fullword ascii /* b64: task.dns[ */

   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}