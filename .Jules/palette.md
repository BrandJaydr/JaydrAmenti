## 2025-05-15 - [Pluralization in i18n]
**Learning:** When refactoring a translation utility to handle placeholders like `{count}`, ensure that the argument is passed to the underlying retrieval method in both singular and plural branches to avoid unformatted placeholders in the UI.
**Action:** Always verify that all conditional branches in i18n logic correctly interpolate required placeholders.
