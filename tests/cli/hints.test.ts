import { describe, expect, it } from 'vitest';
import { accountInstructions } from '../../src/cli/ui/hints.js';

describe('router account instructions', () => {
  it.each(['remote', 'lan'] as const)('states the exact %s account privileges', mode => {
    const text = accountInstructions(mode, 'mcp_agent', 'generated-password');
    const normalized = text.replace(/\s+/g, ' ');
    expect(text).toContain('HTTP Proxy');
    expect(text).toContain('Prohibit saving system settings');
    expect(text).toContain('Read and write');
    expect(text).toContain('Read-only');
    expect(normalized).toContain('MCP profile created by this wizard remains read-only');
  });
});
