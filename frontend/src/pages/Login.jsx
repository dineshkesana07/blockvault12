import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Eye, EyeOff, LockKeyhole } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { authAPI, API_BASE_URL } from '../services/api';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const normalizedEmail = email.trim();

    if (!normalizedEmail || !password) {
      setError('Enter your email and master password to continue.');
      return;
    }

    setLoading(true);
    try {
      const res = await authAPI.login(normalizedEmail, password);
      if (res.data && res.data.token) {
        login(res.data.user || { name: normalizedEmail, email: normalizedEmail }, res.data.token);
        navigate('/dashboard');
      } else {
        setError('Login failed. Please check your credentials.');
      }
    } catch (err) {
      let msg = 'Login failed. Please check your credentials.';
      if (err.response?.data?.error) {
        msg = err.response.data.error;
      } else if (err.response?.data?.message) {
        msg = err.response.data.message;
      } else if (err.code === 'ECONNABORTED' || err.message?.includes('timeout')) {
        msg = 'Connection timed out. Please verify that the C++ backend is responding.';
      } else if (err.message === 'Network Error' || !err.response) {
        msg = `Unable to connect to backend server at ${API_BASE_URL}. Please ensure the C++ backend is running on port 10000.`;
      } else if (err.response?.status === 401) {
        msg = 'Invalid email or master password.';
      } else if (err.response?.status === 500) {
        msg = 'Server encountered an internal error. Please try again later.';
      } else if (err.message) {
        msg = err.message;
      }
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="flex min-h-[calc(100vh-4rem)] items-center justify-center bg-gradient-to-b from-primary via-black to-secondary px-4 py-10 text-white">
      <section className="w-full max-w-md rounded-2xl border border-white/10 bg-secondary/95 p-6 shadow-2xl sm:p-8">
        <div className="mb-6 flex items-center gap-3">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-accentPurple to-accentBlue">
            <LockKeyhole className="h-5 w-5 text-white" aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-2xl font-bold">Welcome back</h1>
            <p className="text-sm text-gray-400">Unlock your secure vault.</p>
          </div>
        </div>
        {error && (
          <div role="alert" className="mb-5 rounded-lg border border-red-500/60 bg-red-950/60 p-3 text-sm text-red-200">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label htmlFor="login-email" className="mb-2 block text-sm font-medium text-gray-200">Email</label>
            <input
              id="login-email"
              name="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="w-full rounded-lg border border-gray-600 bg-primary px-4 py-3 text-white placeholder:text-gray-500 focus:border-accentBlue focus:outline-none focus:ring-2 focus:ring-accentBlue/30"
              placeholder="you@example.com"
              autoComplete="email"
              required
              disabled={loading}
            />
          </div>
          <div>
            <label htmlFor="login-password" className="mb-2 block text-sm font-medium text-gray-200">Master password</label>
            <div className="relative">
              <input
                id="login-password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                maxLength={1024}
                className="w-full rounded-lg border border-gray-600 bg-primary px-4 py-3 pr-12 text-white placeholder:text-gray-500 focus:border-accentBlue focus:outline-none focus:ring-2 focus:ring-accentBlue/30"
                placeholder="Enter your master password"
                autoComplete="current-password"
                required
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowPassword((visible) => !visible)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                aria-pressed={showPassword}
                className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-400 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accentBlue"
              >
                {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
              </button>
            </div>
          </div>
          <button
            type="submit"
            className="w-full rounded-lg bg-accentPurple px-4 py-3 font-semibold text-white transition hover:bg-violet-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-offset-2 focus-visible:ring-offset-secondary disabled:cursor-not-allowed disabled:opacity-60"
            disabled={loading}
          >
            {loading ? 'Unlocking vault...' : 'Log in'}
          </button>
        </form>
        <p className="mt-6 text-center text-sm text-gray-400">
          New to BlockVault? <Link to="/signup" className="font-semibold text-accentBlue underline-offset-4 hover:underline">Create an account</Link>
        </p>
      </section>
    </main>
  );
}
