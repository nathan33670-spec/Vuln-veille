import { ApiError, setCsrfToken } from "@vv/api-client";
import { Alert, Button, Dialog, TextField } from "@vv/ui";
import {
  createContext,
  type FormEvent,
  type ReactNode,
  useCallback,
  useContext,
  useRef,
  useState,
} from "react";
import { useTranslation } from "react-i18next";

import { useAuthContext, useMe } from "./context";
import { errorMessage } from "./errors";

type Runner = <T>(action: () => Promise<T>) => Promise<T>;

const StepUpContext = createContext<Runner | null>(null);

/** Runs an action; if the API asks for a step-up, prompts for it, then retries once. */
export function useStepUp(): Runner {
  const runner = useContext(StepUpContext);
  if (!runner) throw new Error("StepUpProvider missing");
  return runner;
}

export function StepUpProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const { api } = useAuthContext();
  const me = useMe().data;
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string>();
  const pending = useRef<{ resolve: () => void; reject: (e: unknown) => void } | null>(null);
  const usesCode = me?.mfa_enabled ?? true;

  const run: Runner = useCallback(async (action) => {
    try {
      return await action();
    } catch (err) {
      if (!(err instanceof ApiError && err.code === "step_up_required")) throw err;
      await new Promise<void>((resolve, reject) => {
        pending.current = { resolve, reject };
        setValue("");
        setError(undefined);
        setOpen(true);
      });
      return action();
    }
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      const result = await api.stepUp(usesCode ? { code: value } : { password: value });
      setCsrfToken(result.csrf_token);
      setOpen(false);
      pending.current?.resolve();
      pending.current = null;
    } catch (err) {
      setError(errorMessage(t, err));
    }
  }

  function cancel() {
    setOpen(false);
    pending.current?.reject(new ApiError(403, "step_up_required"));
    pending.current = null;
  }

  return (
    <StepUpContext.Provider value={run}>
      {children}
      <Dialog open={open} title={t("auth.stepUpTitle")} onClose={cancel}>
        <form className="vv-form" onSubmit={submit}>
          <p>{usesCode ? t("auth.stepUpPromptCode") : t("auth.stepUpPromptPassword")}</p>
          {error ? <Alert>{error}</Alert> : null}
          <TextField
            label={usesCode ? t("auth.code") : t("auth.password")}
            type={usesCode ? "text" : "password"}
            inputMode={usesCode ? "numeric" : undefined}
            autoComplete={usesCode ? "one-time-code" : "current-password"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            required
            autoFocus
          />
          <div className="vv-actions">
            <Button type="submit">{t("auth.confirm")}</Button>
            <Button variant="secondary" onClick={cancel}>
              {t("auth.cancel")}
            </Button>
          </div>
        </form>
      </Dialog>
    </StepUpContext.Provider>
  );
}
