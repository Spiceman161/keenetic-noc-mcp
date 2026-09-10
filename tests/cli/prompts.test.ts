import { describe, expect, it, vi } from 'vitest';
import { createPromptAdapter } from '../../src/cli/ui/prompts.js';

describe('Enquirer terminal adapter', () => {
  it('passes the default choice index to the arrow-key select prompt', async () => {
    const run = vi.fn(async (_question: unknown) => ({ answer: 'lan' }));
    const ui = createPromptAdapter(run, { write: vi.fn() });
    await expect(ui.select('Mode', [
      { value: 'remote', label: 'Remote' }, { value: 'lan', label: 'LAN' }
    ], 'remote')).resolves.toEqual({ kind: 'value', value: 'lan' });
    expect(run.mock.calls[0]?.[0]).toMatchObject({ type: 'select', initial: 0 });
  });

  it.each([
    [{ name: 'escape' }, 'back'],
    [{ name: 'c', ctrl: true }, 'cancel']
  ] as const)('maps navigation cancellation without a real TTY', async (keypress, kind) => {
    const run = vi.fn(async (question: unknown) => {
      const onCancel = (question as { onCancel: (...args: unknown[]) => boolean }).onCancel;
      onCancel('answer', '', { state: { keypress } });
      throw new Error('cancelled');
    });
    const ui = createPromptAdapter(run, { write: vi.fn() });
    await expect(ui.input('Name')).resolves.toEqual({ kind });
  });

  it('waits for prompt cleanup before returning cancellation', async () => {
    const lifecycle: string[] = [];
    const run = vi.fn(async (question: unknown) => {
      lifecycle.push('raw:on', 'listener:on');
      const onCancel = (question as { onCancel: (...args: unknown[]) => boolean }).onCancel;
      onCancel('answer', '', { state: { keypress: { name: 'c', ctrl: true } } });
      lifecycle.push('listener:off', 'raw:off');
      throw new Error('cancelled');
    });
    const ui = createPromptAdapter(run, { write: vi.fn() });
    await expect(ui.input('Name')).resolves.toEqual({ kind: 'cancel' });
    expect(lifecycle).toEqual(['raw:on', 'listener:on', 'listener:off', 'raw:off']);
  });
});
