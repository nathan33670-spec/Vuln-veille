import {
  autocompletion,
  type CompletionContext,
  type CompletionResult,
  completionKeymap,
} from "@codemirror/autocomplete";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { EditorState } from "@codemirror/state";
import { EditorView, keymap, placeholder as placeholderText } from "@codemirror/view";
import { useEffect, useId, useRef } from "react";

/**
 * A CodeMirror 6 field for JMESPath expressions and Liquid templates.
 *
 * Mounted in a shadow root: CodeMirror's styles then go through a constructed
 * stylesheet (adoptedStyleSheets), which the production CSP allows, instead of a
 * <style> element, which `style-src 'self'` forbids.
 */
export function CodeField({
  label,
  value,
  onChange,
  completions,
  multiline = false,
  placeholder,
  hint,
  error,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  completions: readonly string[];
  multiline?: boolean;
  placeholder?: string | undefined;
  hint?: string | undefined;
  error?: string | undefined;
}) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const latest = useRef({ onChange, completions });
  const labelId = useId();
  const hintId = useId();

  useEffect(() => {
    latest.current = { onChange, completions };
  });

  useEffect(() => {
    const element = host.current;
    if (!element) return;
    const root = element.shadowRoot ?? element.attachShadow({ mode: "open" });
    const parent = document.createElement("div");
    root.appendChild(parent);
    const source = (context: CompletionContext): CompletionResult | null => {
      const word = context.matchBefore(/[\w.$]+/);
      if (!word || (word.from === word.to && !context.explicit)) return null;
      return {
        from: word.from,
        options: latest.current.completions.map((label) => ({ label })),
        validFor: /^[\w.$]*$/,
      };
    };
    const extensions = [
      history(),
      keymap.of([...completionKeymap, ...defaultKeymap, ...historyKeymap]),
      autocompletion({ override: [source] }),
      EditorView.updateListener.of((update) => {
        if (update.docChanged) latest.current.onChange(update.state.doc.toString());
      }),
      EditorView.contentAttributes.of({
        "aria-labelledby": labelId,
        "aria-describedby": hintId,
        "aria-multiline": String(multiline),
        spellcheck: "false",
      }),
      EditorView.theme({
        "&": {
          border: "1px solid var(--vv-border)",
          borderRadius: "4px",
          background: "var(--vv-bg)",
          color: "var(--vv-text)",
          fontSize: "0.9rem",
        },
        "&.cm-focused": { outline: "2px solid var(--vv-accent)" },
        ".cm-content": {
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          minHeight: multiline ? "4.5em" : "1.5em",
          caretColor: "var(--vv-text)",
        },
        ".cm-tooltip": { background: "var(--vv-surface)", color: "var(--vv-text)" },
      }),
      ...(multiline
        ? [EditorView.lineWrapping]
        : // A single line: newlines typed or pasted are dropped.
          [EditorState.transactionFilter.of((tr) => (tr.newDoc.lines > 1 ? [] : tr))]),
      ...(placeholder ? [placeholderText(placeholder)] : []),
    ];
    view.current = new EditorView({
      parent,
      root,
      state: EditorState.create({ doc: value, extensions }),
    });
    return () => {
      view.current?.destroy();
      view.current = null;
      parent.remove();
    };
    // Built once per field; the value is synchronised below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [multiline]);

  useEffect(() => {
    const current = view.current;
    if (current && current.state.doc.toString() !== value) {
      current.dispatch({ changes: { from: 0, to: current.state.doc.length, insert: value } });
    }
  }, [value]);

  return (
    <div className="vv-field">
      <span id={labelId} className="vv-label">
        {label}
      </span>
      <div ref={host} className="vv-code-field" data-testid={`code-${label}`} />
      <span id={hintId} className={error ? "vv-field-error" : "vv-field-hint"}>
        {error ?? hint ?? ""}
      </span>
    </div>
  );
}
