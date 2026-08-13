DEPLOY FREEZE

Start: Fri 2026-08-14, 6pm
End: Pi verified healthy at new location

No commits to main. No config changes on the Pi.
Cron gap during the move is expected and planned, not a
detection failure.

Resume checklist:
- Pi powers on, SSH reachable at new IP (DHCP will reassign,
  check the new router's device list)
- vcgencmd get_throttled returns 0x0
- vcgencmd measure_temp reasonable
- crontab -l intact
- journalctl -u cron shows firing on the 5-min cadence
- sentinel-triage --view shows fresh records
- One alert received end to end
- Redo static IP reservation on the new router
