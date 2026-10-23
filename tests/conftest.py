import os

from hypothesis import settings

# Fuzzing depth: "ci" runs on every push; HYPOTHESIS_PROFILE=deep for a thorough local pass.
settings.register_profile("ci", max_examples=300)
settings.register_profile("deep", max_examples=5000)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "ci"))
