## 2025-05-15 - [Sherlock UI Streaming]
**Learning:** For CLI tools that wrap long-running subprocesses, using `process.communicate()` is a poor UX as it blocks the UI and provides no feedback until completion. Implementing real-time streaming with `process.stdout.readline()` combined with `console.status` significantly improves the perceived performance and responsiveness.
**Action:** Always prefer asynchronous or line-by-line output streaming for long-running subprocesses in CLI tools to keep the user informed.

## 2025-05-15 - [Prompt Validation Choices]
**Learning:** `rich.prompt.Prompt` with a `choices` list strictly enforces input. If a shortcut key (like 'S' for Sherlock) is not in the choices list, it will be rejected even if the logic exists to handle it.
**Action:** Ensure all valid keyboard shortcuts for a menu are explicitly included in the `choices` parameter of `Prompt.ask`.
