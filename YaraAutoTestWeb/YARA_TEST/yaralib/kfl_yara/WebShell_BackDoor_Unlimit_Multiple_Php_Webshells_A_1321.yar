rule WebShell_BackDoor_Unlimit_Multiple_Php_Webshells_A_1321 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files multiple_php_webshells"
    family = "Multiple"
    hacker = "None"
    hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
    hash1 = "911195a9b7c010f61b66439d9048f400"
    hash2 = "be0f67f3e995517d18859ed57b4b4389"
    hash3 = "eddf7a8fde1e50a7f2a817ef7cece24f"
    hash4 = "8023394542cddf8aee5dec6072ed02b5"
    hash5 = "eed14de3907c9aa2550d95550d1a2d5f"
    hash6 = "817671e1bdc85e04cc3440bbd9288800"
    hash7 = "7101fe72421402029e2629f3aaed6de7"
    hash8 = "f618f41f7ebeb5e5076986a66593afd1"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Multiple.Php.Webshells.A"
    threattype = "BackDoor"
  strings:
    $s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
    $s2 = "sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0"
    $s4 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg"
  condition:
    2 of them
}