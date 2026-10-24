import { useEffect, useState } from "react";
import { ApiError } from "../api/errors";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  /** The HTTP status of a refused call (an ApiError), else null. */
  errorStatus: number | null;
  reload: () => void;
}

function message(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}

/**
 * Run an async fetch on mount and whenever `deps` change. `reload()` re-runs it.
 * `fn` is intentionally not part of the dependency list — pass real deps.
 */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    setErrorStatus(null);
    fn()
      .then((d) => {
        if (alive) {
          setData(d);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (alive) {
          setError(message(e));
          setErrorStatus(e instanceof ApiError ? e.status : null);
          setLoading(false);
        }
      });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return { data, loading, error, errorStatus, reload: () => setNonce((n) => n + 1) };
}
