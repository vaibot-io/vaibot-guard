import { defineProject } from 'vitest/config'

export default defineProject({
  test: {
    // Tests use node:test, not vitest — run via `node --test tests/`
    include: [],
  },
})
