---
name: tor-skill
description: Synthetic test fixture — a skill that declares Tor as its required network path.
metadata:
  mordred:
    network_requirements: tor
---

# Tor Skill (test fixture)

This skill is used by `tests/test_install_wrapper.py` to assert that
strict-mode policy allows installation of Tor-declared skills.

Its executable counterpart, `network_probe.py`, is the network
operation this `network_requirements: tor` declaration is about. The
integration test `tests/integration/test_tor.py::TestTorSkillEndToEnd`
runs it through a live Tor circuit; the hermetic
response-handling tests live in `tests/test_tor_skill_fixture.py`.
