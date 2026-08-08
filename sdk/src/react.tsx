/**
 * React components for @zcashme/login
 *
 * Usage:
 *   import { ZcashMeButton, useZcashMeCallback } from '@zcashme/login/react';
 */

import { useRef, useState, useCallback, useEffect } from 'react';
import type { ZcashMeOptions, ZcashMeSession, ZcashMeUser } from './types';
import { ZcashMeAuth } from './client';

export interface ZcashMeButtonProps extends ZcashMeOptions {
  /** Button text (default: "Sign in with ZcashMe") */
  label?: string;
  /** Called when login redirect starts (before browser navigates away) */
  onStart?: () => void;
  /** Called if the redirect fails to start */
  onError?: (error: string) => void;
  /** Additional CSS classes for the button */
  className?: string;
  /** Disable the button */
  disabled?: boolean;
}

export function ZcashMeButton({
  label = 'Sign in with ZcashMe',
  onStart,
  onError,
  className = '',
  disabled = false,
  ...options
}: ZcashMeButtonProps) {
  const clientRef = useRef<ZcashMeAuth | null>(null);
  const [loading, setLoading] = useState(false);

  if (!clientRef.current) {
    clientRef.current = new ZcashMeAuth(options);
  }

  const handleClick = useCallback(async () => {
    if (disabled || loading) return;
    setLoading(true);
    onStart?.();

    try {
      await clientRef.current!.loginWithRedirect();
    } catch (err) {
      setLoading(false);
      onError?.(err instanceof Error ? err.message : 'Login failed');
    }
  }, [disabled, loading, onStart, onError]);

  return (
    <button
      onClick={handleClick}
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition-all ${
        disabled || loading
          ? 'opacity-50 cursor-not-allowed bg-gray-100 text-gray-400 border border-gray-200'
          : 'bg-white text-gray-900 border border-gray-300 hover:border-blue-600 hover:text-blue-600'
      } ${className}`}
    >
      {loading ? (
        <span className="inline-block w-4 h-4 border-2 border-gray-300 border-t-blue-600 rounded-full animate-spin" />
      ) : (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.5" opacity="0.3"/>
          <path d="M12 4v16M4 12h16" stroke="currentColor" strokeWidth="1.5" opacity="0.5"/>
          <text x="12" y="15" textAnchor="middle" fontSize="9" fontWeight="bold" fill="currentColor">Z</text>
        </svg>
      )}
      {label}
    </button>
  );
}

/**
 * Hook for handling the OAuth callback on the redirect page.
 *
 * Usage (on your callback page):
 *   const { session, error, isLoading } = useZcashMeCallback({
 *     clientId: 'pgpz',
 *     redirectUri: 'https://community.pgpz.org/api/auth/callback/zcashme',
 *   });
 */
export function useZcashMeCallback(options: ZcashMeOptions) {
  const [session, setSession] = useState<ZcashMeSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const clientRef = useRef<ZcashMeAuth | null>(null);
  if (!clientRef.current) {
    clientRef.current = new ZcashMeAuth(options);
  }

  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        const result = await clientRef.current!.handleRedirectCallback();
        if (!cancelled) {
          setSession(result);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Callback handling failed');
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    })();

    return () => { cancelled = true; };
  }, []);

  return { session, error, isLoading };
}

/**
 * Hook for accessing the current session (if logged in).
 * Returns null if no session or expired.
 */
export function useZcashMeSession(options: ZcashMeOptions) {
  const [session, setSession] = useState<ZcashMeSession | null>(null);

  const clientRef = useRef<ZcashMeAuth | null>(null);
  if (!clientRef.current) {
    clientRef.current = new ZcashMeAuth(options);
  }

  useEffect(() => {
    setSession(clientRef.current!.getSession());
  }, []);

  return session;
}