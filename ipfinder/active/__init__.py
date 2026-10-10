"""Active probing (L10): packets sent straight to the target. Runs only with
--active after the user confirms they are authorised to test the system.

Deliberately limited to what the plan allows without written permission:
round-trip time, the network path and the TLS certificate on port 443. There is
no port scanning; open ports come passively from Shodan InternetDB.
"""
