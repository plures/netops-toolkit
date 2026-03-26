"""
Configuration change management.

Provides a full safe-change workflow for network devices:

* :mod:`netops.change.diff`     — semantic-aware config diff engine
* :mod:`netops.change.plan`     — change approval workflow (plan → review → apply)
* :mod:`netops.change.push`     — safe config push with pre/post diff and confirm timer
* :mod:`netops.change.rollback` — automated rollback with pre/post health validation
"""
