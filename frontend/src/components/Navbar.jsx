import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export default function Navbar() {
  const { isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  return (
    <nav
      aria-label="Main navigation"
      className="sticky top-0 z-50 bg-paper border-b border-chalk flex items-center justify-between px-4 sm:px-6 py-3"
    >
      <Link
        to="/"
        className="font-serif font-bold text-lg text-charcoal"
      >
        BlockVault
      </Link>

      <div className="flex items-center gap-4 sm:gap-5">
        {isAuthenticated ? (
          <>
            <Link
              to="/dashboard"
              className="text-sm text-stone transition-colors duration-100 hover:text-charcoal"
            >
              Dashboard
            </Link>
            <button
              onClick={handleLogout}
              className="text-sm text-stone transition-colors duration-100 hover:text-accent"
            >
              Logout
            </button>
          </>
        ) : (
          <>
            <Link
              to="/login"
              className="text-sm text-stone transition-colors duration-100 hover:text-charcoal"
            >
              Login
            </Link>
            <Link
              to="/signup"
              className="rounded border border-charcoal px-3 py-1.5 text-sm text-charcoal transition-colors duration-100 hover:bg-charcoal hover:text-paper"
            >
              Sign Up
            </Link>
          </>
        )}
      </div>
    </nav>
  );
}
