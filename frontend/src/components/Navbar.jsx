import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Lock } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export default function Navbar() {
  const { isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  return (
    <nav aria-label="Main navigation" className="sticky top-0 z-50 bg-primary text-white flex items-center justify-between gap-3 px-3 sm:px-6 py-3 shadow-glass border-b border-white/10">
      <Link to="/" className="flex shrink-0 items-center gap-2 rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accentBlue">
        <div className="w-8 h-8 bg-gradient-to-br from-accentPurple to-accentBlue rounded-md flex items-center justify-center">
          <Lock className="w-5 h-5 text-white" />
        </div>
        <span className="font-bold text-lg sm:text-xl">BlockVault</span>
      </Link>
      <div className="flex items-center gap-2 sm:gap-4">
        <Link to="/" className="hidden md:inline rounded px-2 py-2 text-sm text-gray-200 transition hover:text-accentBlue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accentBlue">Home</Link>
        {isAuthenticated ? (
          <>
            <Link to="/dashboard" className="rounded px-2 py-2 text-sm text-gray-100 transition hover:text-accentBlue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accentBlue">Dashboard</Link>
            <button
              onClick={handleLogout}
              className="rounded border border-gray-600 px-3 py-2 text-sm font-medium text-gray-100 transition hover:border-red-400 hover:text-red-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400"
            >
              Logout
            </button>
          </>
        ) : (
          <>
            <Link to="/login" className="rounded-md border border-accentBlue px-3 py-2 text-sm font-semibold text-white transition hover:bg-accentBlue hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white">Login</Link>
            <Link to="/signup" className="rounded-md bg-accentPurple px-3 py-2 text-sm font-semibold text-white transition hover:bg-violet-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white">Sign Up</Link>
          </>
        )}
      </div>
    </nav>
  );
}
