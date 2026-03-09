## 2025-05-14 - Subprocess Status Feedback
**Learning:** For terminal-based tools that invoke long-running external processes (like Sherlock), users lack feedback on whether the app has hung. Using `rich.console.status` with a spinner provides immediate visual confirmation of progress.
**Action:** Always wrap external process calls or slow I/O in a status context manager with a localized descriptive message.

## 2025-05-14 - Micro-UX Scope Constraint
**Learning:** In a large terminal interface with many repetitive UI patterns (like "Press Enter to continue"), a full-scale refactoring to centralize the pattern can exceed line-count constraints and bloat PRs.
**Action:** Prioritize high-impact visual feedback (spinners) over structural refactorings when the goal is a "micro-UX" improvement, unless the refactoring is required for the specific fix.
