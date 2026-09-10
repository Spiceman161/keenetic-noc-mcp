import Enquirer from 'enquirer';

export type PromptResult<T> =
  | { kind: 'value'; value: T }
  | { kind: 'back' }
  | { kind: 'cancel' };

export interface PromptChoice<T extends string> {
  value: T;
  label: string;
  hint?: string;
}

export interface PromptAdapter {
  input(message: string, initial?: string): Promise<PromptResult<string>>;
  select<T extends string>(message: string, choices: readonly PromptChoice<T>[], initial?: T): Promise<PromptResult<T>>;
  confirm(message: string, initial: boolean): Promise<PromptResult<boolean>>;
  output(message: string): void;
  close(): void;
}

type PromptQuestion = Parameters<typeof Enquirer.prompt>[0];
type PromptRunner = (question: PromptQuestion) => Promise<Record<string, unknown>>;

function navigation(prompt: unknown): 'back' | 'cancel' {
  const state = (prompt as { state?: { keypress?: { name?: string; ctrl?: boolean } } }).state;
  const key = state?.keypress;
  return key?.name === 'escape' && key.ctrl !== true ? 'back' : 'cancel';
}

/** Enquirer adapter. Arrow handling belongs to Enquirer's select prompt. */
export function createPromptAdapter(
  run: PromptRunner = question => Enquirer.prompt(question) as Promise<Record<string, unknown>>,
  stdout: Pick<NodeJS.WriteStream, 'write'> = process.stdout,
  stdin: NodeJS.ReadStream = process.stdin
): PromptAdapter {
  let cancelled: 'back' | 'cancel' = 'cancel';
  const ask = async <T>(question: PromptQuestion): Promise<PromptResult<T>> => {
    cancelled = 'cancel';
    try {
      const answer = await run(question);
      return { kind: 'value', value: answer['answer'] as T };
    } catch {
      return { kind: cancelled };
    }
  };
  const onCancel = (_name: string, _value: unknown, prompt: Enquirer.Prompt): boolean => {
    cancelled = navigation(prompt);
    return false;
  };
  return {
    input(message, initial) {
      return ask<string>({ type: 'input', name: 'answer', message, ...(initial !== undefined ? { initial } : {}), stdin, stdout: stdout as NodeJS.WriteStream, onCancel });
    },
    select<T extends string>(message: string, choices: readonly PromptChoice<T>[], initial?: T) {
      const index = initial === undefined ? 0 : Math.max(0, choices.findIndex(choice => choice.value === initial));
      return ask<T>({
        type: 'select', name: 'answer', message, initial: index,
        choices: choices.map(choice => ({ name: choice.value, message: choice.label, ...(choice.hint ? { hint: choice.hint } : {}) })),
        stdin, stdout: stdout as NodeJS.WriteStream, onCancel
      });
    },
    confirm(message, initial) {
      return ask<boolean>({ type: 'confirm', name: 'answer', message, initial, stdin, stdout: stdout as NodeJS.WriteStream, onCancel });
    },
    output(message) { stdout.write(`${message}\n`); },
    close() { /* Enquirer restores the TTY after every prompt. */ }
  };
}
