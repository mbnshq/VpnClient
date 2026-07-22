# Resources

Shipped, non-code assets. Populated during Phase 5 (UI) and Phase 8 (installer).

| Directory | Contents |
| --- | --- |
| `icons/` | application icon (`.ico`, all sizes), tray icons for each connection state, per-country flags |
| `images/` | default profile tile artwork, onboarding illustrations |
| `strings/` | localisation catalogues, one JSON file per locale (`en-US.json`, …) |
| `version/` | the Win32 version resource template, populated from `Core/Version.h` |

## Localisation

Strings are keyed, never inlined at a call site. The catalogue format is flat
JSON so it can be handed to translators without tooling:

```json
{
  "dashboard.status.connected": "Connected",
  "dashboard.status.reconnecting": "Reconnecting…",
  "splittunnel.mode.include": "Only selected apps use the VPN"
}
```

`en-US` is the source of truth. A missing key in another locale falls back to
`en-US` rather than rendering the key, so a partial translation degrades
gracefully. Right-to-left locales are supported through the framework's own
flow-direction handling.
