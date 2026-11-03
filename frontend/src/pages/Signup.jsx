import React from 'react';
import { Link } from 'react-router-dom';

export default function Signup() {
  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center">
      <div className="w-full max-w-md p-8 bg-gray-900 text-white rounded-lg shadow-glass border border-gray-700">
        <h2 className="text-2xl font-bold mb-6" style={{ color: '#FF0000' }}>Create Account</h2>
        <form className="space-y-4">
          <input
            className="w-full p-2 bg-gray-800 rounded border border-gray-600 focus:border-accentPurple outline-none"
            placeholder="Full Name"
          />
          <input
            className="w-full p-2 bg-gray-800 rounded border border-gray-600 focus:border-accentPurple outline-none"
            placeholder="Email"
          />
          <input
            className="w-full p-2 bg-gray-800 rounded border border-gray-600 focus:border-accentPurple outline-none"
            placeholder="Username"
          />
          <input
            type="password"
            className="w-full p-2 bg-gray-800 rounded border border-gray-600 focus:border-accentPurple outline-none"
            placeholder="Master Password"
          />
          <button
            type="submit"
            className="w-full py-2 bg-accentPurple text-white font-semibold rounded hover:bg-accentPurple/80 transition"
          >
            Create Account
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

