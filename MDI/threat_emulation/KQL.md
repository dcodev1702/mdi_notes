```console
let EventMapping = datatable(EventID: int, EventName: string)
[
    2503, "Add/Update/Delete Directories",
    2504, "Enable Express settings mode",
    2505, "Enable/Disable domains and OU for sync",
    2506, "Enable/Disable PHS Sync",
    2507, "Enable/Disable Sync start after install",
    2508, "Create ADDS account",
    2509, "Use Existing ADDS account",
    2510, "Create/Update/Delete custom sync rule",
    2511, "Enable/Disable Domain based filtering",
    2512, "Enable/Disable OU based filtering",
    2513, "User Sign-In method changed",
    2514, "Configure new ADFS farm",
    2515, "Enable/Disable Single sign-on",
    2516, "Install web application proxy server",
    2517, "Set Permissions",
    2518, "Change ADDS Connector credential",
    2519, "Reinitialize Entra ID Connector account password",
    2520, "Install ADFS Server",
    2521, "Set ADFS Service Account"
];
Event
| where Source == "Entra Connect Admin Actions"
| extend ['Action'] = tostring(parse_json(RenderedDescription).ActionType)
| join kind=inner (EventMapping) on $left.EventID == $right.EventID
| distinct TimeGenerated, Source, Computer, ['Action'], EventID, EventName, RenderedDescription
| sort by TimeGenerated desc  
| take 1000
```
