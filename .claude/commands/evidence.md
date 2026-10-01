---
description: Regenerate evidence and check that docs contain no hand-written numbers.
---

1. Run `make audit` if hardening changed since the last lynis-after result, then `make simulate` and `make report`.
2. Show `git diff README.md`.
3. Search docs/ and README.md for numbers outside the results block that describe performance or security outcomes. List any that are not traceable to a file in results/.
4. Report results in plain language, including any failed scenario.
