import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { authAPI, API_BASE_URL } from '../services/api';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const email = e.target.username.value.trim();
    const password = e.target.password.value;

    if (!email || !password) {
      setError('Please enter your email and master password.');
      return;
    }

    setLoading(true);
    try {
      const res = await authAPI.login(email, password);
      if (res.data && res.data.token) {
        login(res.data.user || { name: email, email }, res.data.token);
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
    <div className="min-h-screen flex items-center justify-center bg-black text-white">
      <div className="p-8 bg-white text-black rounded-lg shadow-lg max-w-md w-full">
        <h2 className="text-2xl font-bold mb-4">Login</h2>
        {error && (
          <div className="mb-4 p-2 bg-red-100 border border-red-400 text-red-700 text-sm rounded">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit}>
          <input
            name="username"
            type="text"
            className="border p-2 w-full mb-2"
            placeholder="Username or Email"
            autoComplete="email"
            required
            disabled={loading}
          />
          <input
            name="password"
            type="password"
            className="border p-2 w-full mb-4"
            placeholder="Master Password"
            autoComplete="current-password"
            required
            disabled={loading}
          />
          <button
            type="submit"
            className="bg-green-500 text-white px-4 py-2 rounded w-full disabled:opacity-50"
            disabled={loading}
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
        <p className="mt-4 text-center">
          No account? <Link to="/signup" className="text-red-500 underline">Sign up</Link>
        </p>
      </div>
    </div>
  );
}
