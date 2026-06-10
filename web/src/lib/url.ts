// Syncs search/filter/route state to the URL query string (UIX_CONTRACT §5)
// so views are shareable/bookmarkable and survive a refresh.
import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

/** Read/write a single string query param, replacing history (no back-stack spam). */
export function useQueryParam(key: string, defaultValue = ""): [string, (value: string) => void] {
  const [params, setParams] = useSearchParams();
  const value = params.get(key) ?? defaultValue;

  const setValue = useCallback(
    (next: string) => {
      setParams(
        (prev) => {
          const updated = new URLSearchParams(prev);
          if (next === "" || next === defaultValue) {
            updated.delete(key);
          } else {
            updated.set(key, next);
          }
          return updated;
        },
        { replace: true }
      );
    },
    [key, defaultValue, setParams]
  );

  return [value, setValue];
}

/** Read/write a comma-separated list query param (e.g. ?types=attack,defend). */
export function useQueryListParam(key: string): [string[], (values: string[]) => void] {
  const [raw, setRaw] = useQueryParam(key, "");
  const value = raw ? raw.split(",").filter(Boolean) : [];
  const setValue = useCallback((values: string[]) => setRaw(values.join(",")), [setRaw]);
  return [value, setValue];
}
