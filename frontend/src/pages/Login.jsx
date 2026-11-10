import React, { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Eye, EyeOff } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { authAPI } from '../services/api';

const clientId = (import.meta.env.VITE_GOOGLE_CLIENT_ID || '').trim();

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const signingUp = pathname === '/signup';
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [ready, setReady] = useState(() => !!window.google?.accounts?.oauth2);

  useEffect(() => {
    const script = document.getElementById('google-identity-services');
    const onLoad = () => setReady(!!window.google?.accounts?.oauth2);
    const onError = () => setError('Google sign-in could not load. Check your connection and reload this page.');
    onLoad();
    script?.addEventListener('load', onLoad);
    script?.addEventListener('error', onError);
    const timeout = window.setTimeout(() => {
      if (!window.google?.accounts?.oauth2) onError();
    }, 15000);
    return () => {
      script?.removeEventListener('load', onLoad);
      script?.removeEventListener('error', onError);
      window.clearTimeout(timeout);
    };
  }, []);

  const handleSubmit = (event) => {
    event.preventDefault();
    setError('');
    if (signingUp && password !== confirmation) {
      setError('The master passwords do not match.');
      return;
    }
    setLoading(true);
    try {
      const client = window.google.accounts.oauth2.initCodeClient({
        client_id: clientId,
        scope: 'openid email profile',
        ux_mode: 'popup',
        select_account: true,
        callback: async (response) => {
          if (response.error || !response.code) {
            setError('Google sign-in was cancelled or declined. Please try again.');
            setLoading(false);
            return;
          }
          try {
            const result = await authAPI.googleLogin(response.code, password);
            if (!result.data?.token) throw new Error('Sign-in did not create a session.');
            login(result.data.user, result.data.token);
            setPassword('');
            setConfirmation('');
            navigate('/dashboard', { replace: true });
          } catch (requestError) {
            setError(requestError.response?.data?.error || 'Unable to complete sign-in. Please try again.');
          } finally {
            setLoading(false);
          }
        },
        error_callback: () => {
          setError('The Google sign-in window was closed or blocked. Please try again.');
          setLoading(false);
        },
      });
      client.requestCode();
    } catch {
      setError('Google sign-in could not start. Please reload this page and try again.');
      setLoading(false);
    }
  };

  const inputClass = 'w-full bg-paper border border-chalk rounded px-3 py-2.5 text-sm text-charcoal placeholder:text-stone/60 focus:border-charcoal focus:outline-none';

  return (
    <main className="flex min-h-[calc(100vh-3.5rem)] items-center justify-center bg-bone px-4 py-10">
      <section className="w-full max-w-md bg-paper border border-chalk rounded p-8">
        <h1 className="font-serif font-bold text-2xl text-charcoal">{signingUp ? 'Create your vault' : 'Welcome back'}</h1>
        <p className="mt-2 text-sm text-stone max-w-[55ch]">
          {signingUp ? 'Choose a master password, then sign up with Google.' : 'Enter your master password, then sign in with Google.'}
          {' '}Your master password encrypts your vault and is never sent to Google.
        </p>
        {!clientId && <p role="alert" className="mt-5 text-sm text-accent">Google sign-in is not configured yet.</p>}
        {error && <div role="alert" className="mt-5 border border-accent/40 bg-accent/5 text-accent text-sm rounded p-3">{error}</div>}
        <form onSubmit={handleSubmit} className="mt-6 space-y-5">
          <div>
            <label htmlFor="master-password" className="mb-1.5 block text-xs font-medium text-stone uppercase tracking-wide">Master password</label>
            <div className="relative">
              <input id="master-password" type={showPassword ? 'text' : 'password'}
                value={password} onChange={(event) => setPassword(event.target.value)}
                maxLength={1024} minLength={signingUp ? 8 : undefined}
                autoComplete={signingUp ? 'new-password' : 'current-password'}
                required disabled={loading} aria-describedby="password-help" className={`${inputClass} pr-10`} />
              <button type="button" onClick={() => setShowPassword((visible) => !visible)}
                aria-label={showPassword ? 'Hide password' : 'Show password'} aria-pressed={showPassword}
                className="absolute inset-y-0 right-0 flex items-center px-3 text-stone hover:text-charcoal duration-100">
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <p id="password-help" className="mt-2 text-xs text-stone max-w-[55ch]">{signingUp
              ? 'Use at least 8 characters with uppercase, lowercase, a number, and a symbol. Keep this password safe; it is required to unlock your vault.'
              : 'Existing users: use your current vault master password to link your Google account.'}</p>
          </div>
          {signingUp && <div>
            <label htmlFor="confirm-password" className="mb-1.5 block text-xs font-medium text-stone uppercase tracking-wide">Confirm master password</label>
            <input id="confirm-password" type={showPassword ? 'text' : 'password'} value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)} maxLength={1024}
              autoComplete="new-password" required disabled={loading} className={inputClass} />
          </div>}
          <button type="submit" disabled={loading || !ready || !clientId}
            className="flex w-full items-center justify-center gap-3 bg-charcoal text-paper rounded py-2.5 text-sm font-medium hover:bg-ash duration-100 disabled:opacity-40 disabled:cursor-not-allowed">
            <span aria-hidden="true" className="font-bold text-lg">G</span>
            {loading ? 'Completing Google sign-in…' : ready ? 'Continue with Google' : 'Loading Google sign-in…'}
          </button>
        </form>
        <p className="mt-6 text-center text-sm text-stone">
          {signingUp ? 'Already have a vault? ' : 'New to BlockVault? '}
          <Link to={signingUp ? '/login' : '/signup'} onClick={() => { setError(''); setPassword(''); setConfirmation(''); }}
            className="text-accent hover:text-accent-hover duration-100">{signingUp ? 'Sign in' : 'Create a vault'}</Link>
        </p>
      </section>
    </main>
  );
}
