rule WebShell_BackDoor_Unlimit_Vanquish_A_1457 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file vanquish.dll"
    family = "Vanquish"
    hacker = "None"
    hash = "684450adde37a93e8bb362994efc898c"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Vanquish.A"
    threattype = "BackDoor"
  strings:
    $s3 = "You cannot delete protected files/folders! Instead, your attempt has been logged"
    $s8 = "?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU"
    $s9 = "?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z"
  condition:
    all of them
}