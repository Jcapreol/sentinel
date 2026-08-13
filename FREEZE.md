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

## Post-6.1 verification (added 2026-08-13)

Story 6.1 (CoverageGap verdict state) shipped in fbf61c2 but has NOT
been observed on a live record yet. The 5 existing coverage-gap records
predate the change and correctly still render as Deferred/0.500 —
backward compatibility working as designed, not a bug.

To verify after the move: watch for the next 404-fetch event in
cron.log ("persisting a Deferred coverage-gap record"), then confirm
via `sentinel-triage --view` that the NEW record shows the CoverageGap
state with no confidence value, rather than Deferred/0.500.

Base rate is roughly 5 in 157 records, so this may take a while to
appear. Absence is not a failure signal.
