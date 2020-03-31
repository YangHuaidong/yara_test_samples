rule WebShell_BackDoor_Unlimit_Connector_A_1216 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file connector.asp"
    family = "Connector"
    hacker = "None"
    hash = "3ba1827fca7be37c8296cd60be9dc884"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Connector.A"
    threattype = "BackDoor"
  strings:
    $s2 = "If ( AttackID = BROADCAST_ATTACK )"
    $s4 = "Add UNIQUE ID for victims / zombies"
  condition:
    all of them
}