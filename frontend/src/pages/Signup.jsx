import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Eye, EyeOff, KeyRound, MailCheck } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { authAPI, API_BASE_URL } from '../services/api';

const initialForm = { name: '', email: '', password: '', confirmPassword: '' };

function getErrorMessage(error, fallback) {
  if (error.response?.data?.error) return error.response.data.error;
  if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
    return 'The request timed out. Please try again.';
  }
  if (error.message === 'Network Error' || !error.response) {
    return `Unable to connect to the BlockVault server at ${API_BASE_URL}.`;
  }
  return fallback;
}

export default function Signup() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState(initialForm);
  const [step, setStep] = useState('signup');
  const [otp, setOtp] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const timer = window.setInterval(() => {
      setCooldown((remaining) => Math.max(remaining - 1, 0));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [cooldown]);

  const updateForm = (event) => {
    setForm((current) => ({ ...current, [event.target.name]: event.target.value }));
  };

  const handleSignup = async (event) => {
    event.preventDefault();
    setError('');
    setNotice('');

    const name = form.name.trim();
    const email = form.email.trim();
    if (!name || !email || !form.password || !form.confirmPassword) {
      setError('Complete every field to continue.');
      return;
    }
    if (form.password !== form.confirmPassword) {
      setError('The passwords do not match.');
      return;
    }
    if (form.password.length < 8 || form.password.length > 1024 ||
        !/[A-Z]/.test(form.password) || !/[a-z]/.test(form.password) ||
        !/[0-9]/.test(form.password) || !/[^A-Za-z0-9]/.test(form.password)) {
      setError('Use at least 8 characters with uppercase, lowercase, a number, and a symbol.');
      return;
    }

    setLoading(true);
    try {
      const response = await authAPI.signup(name, email, form.password);
      setForm((current) => ({ ...current, name, email }));
      setOtp('');
      setStep('verify');
      setCooldown(response.data?.retry_after_seconds || 60);
      setNotice(response.data?.message || 'Check your email for a verification code.');
    } catch (requestError) {
      if (requestError.response?.status === 502) {
        setStep('verify');
        setCooldown(requestError.response.data?.retry_after_seconds || 60);
      }
      setError(getErrorMessage(requestError, 'Could not start signup. Please try again.'));
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (event) => {
    event.preventDefault();
    setError('');
    setNotice('');
    if (!/^\d{6}$/.test(otp)) {
      setError('Enter the six-digit code from your email.');
      return;
    }

    setLoading(true);
    try {
      const response = await authAPI.verifyOtp(form.email, otp, form.password);
      if (!response.data?.token) {
        setError('Verification could not be completed. Please try again.');
        return;
      }
      login(response.data.user || { name: form.name, email: form.email }, response.data.token);
      setForm(initialForm);
      setOtp('');
      navigate('/dashboard');
    } catch (requestError) {
      setError(getErrorMessage(requestError, 'Could not verify the code. Please try again.'));
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    setError('');
    setNotice('');
    setResending(true);
    try {
      const response = await authAPI.resendOtp(form.email);
      setNotice(response.data?.message || 'If this email can be verified, a new code has been sent.');
      setCooldown(response.data?.retry_after_seconds || 60);
      setOtp('');
    } catch (requestError) {
      const retryAfter = requestError.response?.data?.retry_after_seconds;
      if (retryAfter) setCooldown(retryAfter);
      setError(getErrorMessage(requestError, 'Could not resend the code. Please try again.'));
    } finally {
      setResending(false);
    }
  };

  return (
    <main className="flex min-h-[calc(100vh-4rem)] items-center justify-center bg-gradient-to-b from-primary via-black to-secondary px-4 py-10 text-white">
      <section className="w-full max-w-lg rounded-2xl border border-white/10 bg-secondary/95 p-6 shadow-2xl sm:p-8">
        <div className="mb-6 flex items-center gap-3">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-accentPurple to-accentBlue">
            {step === 'signup'
              ? <KeyRound className="h-5 w-5 text-white" aria-hidden="true" />
              : <MailCheck className="h-5 w-5 text-white" aria-hidden="true" />}
          </span>
          <div>
            <h1 className="text-2xl font-bold">
              {step === 'signup' ? 'Create your vault' : 'Verify your email'}
            </h1>
            <p className="text-sm text-gray-400">
              {step === 'signup'
                ? 'Your master password protects your vault.'
                : 'One last step to secure your account.'}
            </p>
          </div>
        </div>

        {error && (
          <div role="alert" className="mb-5 rounded-lg border border-red-500/60 bg-red-950/60 p-3 text-sm text-red-200">
            {error}
          </div>
        )}
        {notice && (
          <div role="status" aria-live="polite" className="mb-5 rounded-lg border border-green-500/50 bg-green-950/40 p-3 text-sm text-green-200">
            {notice}
          </div>
        )}

        {step === 'signup' ? (
          <form onSubmit={handleSignup} className="space-y-4">
            <div>
              <label htmlFor="signup-name" className="mb-2 block text-sm font-medium text-gray-200">Name</label>
              <input
                id="signup-name"
                name="name"
                type="text"
                value={form.name}
                onChange={updateForm}
                maxLength={100}
                autoComplete="name"
                required
                disabled={loading}
                placeholder="Your name"
                className="w-full rounded-lg border border-gray-600 bg-primary px-4 py-3 text-white placeholder:text-gray-500 focus:border-accentBlue focus:outline-none focus:ring-2 focus:ring-accentBlue/30"
              />
            </div>
            <div>
              <label htmlFor="signup-email" className="mb-2 block text-sm font-medium text-gray-200">Email</label>
              <input
                id="signup-email"
                name="email"
                type="email"
                value={form.email}
                onChange={updateForm}
                maxLength={254}
                autoComplete="email"
                required
                disabled={loading}
                placeholder="you@example.com"
                className="w-full rounded-lg border border-gray-600 bg-primary px-4 py-3 text-white placeholder:text-gray-500 focus:border-accentBlue focus:outline-none focus:ring-2 focus:ring-accentBlue/30"
              />
            </div>
            <div>
              <label htmlFor="signup-password" className="mb-2 block text-sm font-medium text-gray-200">Master password</label>
              <div className="relative">
                <input
                  id="signup-password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={form.password}
                  onChange={updateForm}
                  maxLength={1024}
                  autoComplete="new-password"
                  required
                  disabled={loading}
                  placeholder="Create a strong master password"
                  className="w-full rounded-lg border border-gray-600 bg-primary px-4 py-3 pr-12 text-white placeholder:text-gray-500 focus:border-accentBlue focus:outline-none focus:ring-2 focus:ring-accentBlue/30"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((visible) => !visible)}
                  aria-label={showPassword ? 'Hide passwords' : 'Show passwords'}
                  aria-pressed={showPassword}
                  className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-400 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accentBlue"
                >
                  {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
              <p className="mt-2 text-xs text-gray-400">At least 8 characters, including uppercase, lowercase, a number, and a symbol.</p>
            </div>
            <div>
              <label htmlFor="signup-confirm-password" className="mb-2 block text-sm font-medium text-gray-200">Confirm master password</label>
              <input
                id="signup-confirm-password"
                name="confirmPassword"
                type={showPassword ? 'text' : 'password'}
                value={form.confirmPassword}
                onChange={updateForm}
                maxLength={1024}
                autoComplete="new-password"
                required
                disabled={loading}
                placeholder="Re-enter your master password"
                className="w-full rounded-lg border border-gray-600 bg-primary px-4 py-3 text-white placeholder:text-gray-500 focus:border-accentBlue focus:outline-none focus:ring-2 focus:ring-accentBlue/30"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-accentPurple px-4 py-3 font-semibold text-white transition hover:bg-violet-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-offset-2 focus-visible:ring-offset-secondary disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? 'Sending verification code...' : 'Create account'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleVerify} className="space-y-5">
            <p className="text-sm leading-6 text-gray-300">
              Enter the six-digit code sent to <span className="font-semibold text-white">{form.email}</span>.
              The code expires in five minutes.
            </p>
            <div>
              <label htmlFor="signup-otp" className="mb-2 block text-sm font-medium text-gray-200">Verification code</label>
              <input
                id="signup-otp"
                name="otp"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                value={otp}
                onChange={(event) => setOtp(event.target.value.replace(/\D/g, '').slice(0, 6))}
                autoFocus
                required
                disabled={loading}
                aria-describedby="otp-help"
                placeholder="000000"
                className="w-full rounded-lg border border-gray-600 bg-primary px-4 py-4 text-center font-mono text-2xl tracking-[0.5em] text-white placeholder:text-gray-600 focus:border-accentBlue focus:outline-none focus:ring-2 focus:ring-accentBlue/30"
              />
              <p id="otp-help" className="mt-2 text-xs text-gray-400">Paste the code or type all six digits.</p>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-accentPurple px-4 py-3 font-semibold text-white transition hover:bg-violet-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-offset-2 focus-visible:ring-offset-secondary disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? 'Verifying...' : 'Verify and unlock vault'}
            </button>
            <div className="flex flex-col items-center gap-3 text-sm sm:flex-row sm:justify-between">
              <span className="text-gray-400" aria-live="polite">
                {cooldown > 0 ? `Resend available in ${cooldown}s` : 'Didn’t receive a code?'}
              </span>
              <button
                type="button"
                onClick={handleResend}
                disabled={cooldown > 0 || resending || loading}
                className="rounded px-2 py-1 font-semibold text-accentBlue transition hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accentBlue disabled:cursor-not-allowed disabled:text-gray-500"
              >
                {resending ? 'Sending...' : 'Resend code'}
              </button>
            </div>
          </form>
        )}

        <p className="mt-6 text-center text-sm text-gray-400">
          Already have an account? <Link to="/login" className="font-semibold text-accentBlue underline-offset-4 hover:underline">Log in</Link>
        </p>
      </section>
    </main>
  );
}
