import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = (e) => {
    e.preventDefault();
    const username = e.target.username.value;
    // Dummy login – replace with real API call later
    login({ username });
    navigate('/dashboard');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-black text-white">
      <div className="p-8 bg-white text-black rounded-lg shadow-lg max-w-md w-full">
        <h2 className="text-2xl font-bold mb-4">Login</h2>
        <form onSubmit={handleSubmit}>
          <input name="username" className="border p-2 w-full mb-2" placeholder="Username or Email" />
          <input name="password" type="password" className="border p-2 w-full mb-4" placeholder="Master Password" />
          <button type="submit" className="bg-green-500 text-white px-4 py-2 rounded w-full">Login</button>
        </form>
        <p className="mt-4 text-center">
          No account? <Link to="/signup" className="text-red-500 underline">Sign up</Link>
        </p>
      </div>
    </div>
  );
}

