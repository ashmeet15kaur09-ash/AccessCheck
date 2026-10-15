---
name: Playwright scanner network boundaries
description: Replit Nix runtime dependencies and redirect handling details that affect browser-based SSRF protections.
---

Playwright Chromium downloads do not provide every native runtime library in this Nix environment. Missing shared libraries such as `libnspr4.so` or `libgbm.so.1` can surface as a generic browser-launch failure; install the required system dependencies rather than treating it as a target-site problem.

**Why:** The browser was present, but Chromium could not start until its OS libraries were made available to the workflow.

**How to apply:** When Playwright reports `TargetClosedError` during launch, inspect the browser's shared-library errors (`ldd` is useful) and add the missing native packages through the system dependency manager.

Do not treat `Route.fetch(max_redirects=0)` as a safe redirect boundary. Playwright's fetch helper can follow an upstream redirect inside its request layer before the browser's route handler sees the redirected destination. Handle each redirect manually with automatic following disabled, validate the `Location` target before making the next request, cap redirect hops, and keep a local redirect test that proves a blocked destination receives no request.

**Why:** A private-address redirect reached its destination before the route guard ran when `Route.fetch` handled the redirect internally.

**How to apply:** Preserve explicit redirect validation whenever scanner networking changes, and run the private-redirect integration test before shipping.
