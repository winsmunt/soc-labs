# Sigma Rules - TryHackMe DetectMare

Five experimental rules transcribed from final lab diffs and normalized into standalone YAML documents. The original simulated pull requests list a fictional scenario author; these files identify the lab origin and the learner's tuning work instead.

For PR #5, only the final active condition is included. Earlier `filter_*` blocks were visible in the diff but were removed from the active condition to pass the simulated bypass tests.

These rules are for learning, not direct deployment. In particular, the PR #4 `1 of selection_*` matches individual logon/service events and does not correlate them by host/time.
