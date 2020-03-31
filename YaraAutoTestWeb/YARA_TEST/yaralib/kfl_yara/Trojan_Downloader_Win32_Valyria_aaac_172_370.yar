rule Trojan_Downloader_Win32_Valyria_aaac_172_370
{
    meta:
        judge = "black"
        threatname = "Trojan[Downloader]/Win32.Valyria.aaac"
        threattype = "Downloader"
        family = "Valyria"
        hacker = "None"
        author = "bala"
        refer = "f252a06e629b881f49917a7da7c8ecc4,44935e50d1dfd101674baf194bc4232e,0c2f71a8b5f88dbe385b1fbd9b41836f,24c42891481bdef2a3f59e204edbf52e,1def47e5e4fb48ffae1ce939f90aa010,adb1e854b0a713f6ffd3eace6431c81d,dcd3913fa8b82983cabb36770070861b,bd7d2efdb2a0f352c4b74f2b82e3c7bc,72e046753f0496140b4aa389aee2e300,ccfcd3c63abfb00db901308bbfe11bd1,9146c267ca5ba5510455200cec56aad8,718aa609de2e72106ce3aef5c8733cc3,bc37cd887bde5468305c9b5ac5e7ebbb,7bb3bab08bc7f26b1118f95de7569f80,3e63d55f1e44a71041311c44e34baaa9,f8ebcaf0d441f7ddf5de42c24ac4a542,197c018922237828683783654d3c632a,4f57e6c3813695c628e3ba14b266292c,f202c5bc52924b75da8abedc97044007,ea86466d4cb5588b35e5adc4f4b73cec,34a7d5bcb9ea8253244d6053e4537379,79b78feaa87174f10a5fd0a02d2fa9dc,045c95e8120cc712d502dff0426f2bc2,5432363a0f644e3988fe56eefe6a668c,6318e219b7f6e7f96192e0cdfea1742c"
        comment = "None"
        date = "2018-07-12"
        description = "None"
    strings:
      $x1 = "Get-Content $env:Public\\Libraries\\update.vbs) -replace" ascii
      $x2 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {waitfor haha /T 2}\" & Chr(34), 0" fullword ascii
      $x3 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
      $s4 = "CreateObject(\"WScript.Shell\").Run cmd, 0o" fullword ascii
      /* Base64 encode config */
      /* $global:myhost = */
      $b1 = "JGdsb2JhbDpteWhvc3QgP" ascii
      /* HOME="%public%\Libraries\" */
      $b2 = "SE9NRT0iJXB1YmxpYyVcTGlicmFyaWVzX" ascii
      /* Set wss = CreateObject("wScript.Shell") */
      $b3 = "U2V0IHdzcyA9IENyZWF0ZU9iamVjdCgid1NjcmlwdC5TaGV" ascii
      /* $scriptdir = Split-Path -Parent -Path $ */
      $b4 = "JHNjcmlwdGRpciA9IFNwbGl0LVBhdGggLVBhcmVudCAtUGF0aCA" ascii
      /* \x0aSet wss = CreateObject("wScript.Shell") */
      $b5 = "DQpTZXQgd3NzID0gQ3JlYXRlT2JqZWN" ascii
      /* whoami & hostname */
      $b6 = "d2hvYW1pICYgaG9zdG5hb" ascii
 
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 700KB and 1 of them )
}