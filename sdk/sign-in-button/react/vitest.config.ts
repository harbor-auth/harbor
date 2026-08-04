// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    // @testing-library/react registers its automatic post-test DOM
    // cleanup against the global `afterEach` if one is present at import
    // time; `globals: true` is what makes that hook available.
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["*.test.tsx"],
  },
});
