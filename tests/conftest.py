import os

# the apps the tests start never look for updates on the network (tests/test_updates.py checks that part offline)
os.environ.setdefault("DECOMP_UPDATES", "off")
# imports don't start Ghidra in the background for drafts (tests/test_sms.py runs it once, on purpose)
os.environ.setdefault("DECOMP_GHIDRA_DRAFTS", "off")
