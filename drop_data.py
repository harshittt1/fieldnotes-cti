"""Retired cleanup helper. Deleting MISP events also removes their indicators.

This legacy script is intentionally disabled so it cannot silently reduce the
verified event collection. Use the recoverable repair_event_collection script
for the synthetic feed rows that were incorrectly stored as events.
"""

raise SystemExit("Disabled: this script deletes valid MISP events and linked indicators.")
