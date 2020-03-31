rule WebShell_BackDoor_Unlimit_Rknt_Zip_Folder_Rknt_A_1408 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file RkNT.dll"
    family = "Rknt"
    hacker = "None"
    hash = "5f97386dfde148942b7584aeb6512b85"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Rknt.Zip.Folder.Rknt.A"
    threattype = "BackDoor"
  strings:
    $s0 = "PathStripPathA"
    $s1 = "`cLGet!Addr%"
    $s2 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
    $s3 = "oQToOemBuff* <="
    $s4 = "ionCdunAsw[Us'"
    $s6 = "CreateProcessW: %S"
    $s7 = "ImageDirectoryEntryToData"
  condition:
    all of them
}