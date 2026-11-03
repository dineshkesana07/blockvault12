import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { authAPI } from '../services/api';

export default function Signup() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const name = e.target.name.value.trim();
    const email = e.target.email.value.trim();
    const password = e.target.password.value;

    if (!name || !email || !password) {
      setError('Please fill in all required fields.');
      return;
    }

    setLoading(true);
    try {
      const res = await authAPI.register(name, email, password);
      if (res.data && res.data.token) {
        login(res.data.user || { name, email }, res.data.token);
        navigate('/dashboard');
      } else {
        setError('Failed to create account.');
      }
    } catch (err) {
      const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Registration failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center">
      <div className="w-full max-w-md p-8 bg-gray-900 text-white rounded-lg shadow-glass border border-gray-700">
        <h2 className="text-2xl font-bold mb-6" style={{ color: '#FF0000' }}>Create Account</h2>
        {error && (
          <div className="mb-4 p-2 bg-red-900/50 border border-red-500 text-red-200 text-sm rounded">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            name="name"
            type="text"
            className="w-full p-2 bg-gray-800 rounded border border-gray-600 focus:border-accentPurple outline-none"
            placeholder="Full Name"
            autoComplete="name"
            required
            disabled={loading}
          />
          <input
            name="email"
            type="email"
            className="w-full p-2 bg-gray-800 rounded border border-gray-600 focus:border-accentPurple outline-none"
            placeholder="Email"
            autoComplete="email"
            required
            disabled={loading}
          />
          <input
            name="username"
            type="text"
            className="w-full p-2 bg-gray-800 rounded border border-gray-600 focus:border-accentPurple outline-none"
            placeholder="Username (optional)"
            autoComplete="username"
            disabled={loading}
          />
          <input
            name="password"
            type="password"
            className="w-full p-2 bg-gray-800 rounded border border-gray-600 focus:border-accentPurple outline-none"
            placeholder="Master Password"
            autoComplete="new-password"
            required
            disabled={loading}
          />
          <button
            type="submit"
            className="w-full py-2 bg-accentPurple text-white font-semibold rounded hover:bg-accentPurple/80 transition disabled:opacity-50"
            disabled={loading}
          >
            {loading ? 'Creating Account...' : 'Create Account'}
          </button>
        </form>
        <p className="mt-4 text-center">
          Already have an account?{' '}
          <Link to="/login" className="text-green-500 underline">Login</Link>
        </p>
      </div>
    </div>
  );
}
