import { useMemo } from "react";

type CompositionHandlers<T extends HTMLElement> = {
  onCompositionStart?: (event: React.CompositionEvent<T>) => void;
  onCompositionEnd?: (event: React.CompositionEvent<T>) => void;
  onKeyDown?: (event: React.KeyboardEvent<T>) => void;
};

export function useComposition<T extends HTMLElement>(
  handlers: CompositionHandlers<T>
): CompositionHandlers<T> {
  return useMemo(
    () => ({
      onCompositionStart: handlers.onCompositionStart,
      onCompositionEnd: handlers.onCompositionEnd,
      onKeyDown: handlers.onKeyDown,
    }),
    [handlers.onCompositionStart, handlers.onCompositionEnd, handlers.onKeyDown]
  );
}
