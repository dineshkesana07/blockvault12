import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Lock } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  return (
    <nav className="bg-primary text-white flex items-center justify-between px-6 py-3 shadow-glass">
      <Link to="/" className="flex items-center gap-2">
        <div className="w-8 h-8 bg-gradient-to-br from-accentPurple to-accentBlue rounded-md flex items-center justify-center">
          <Lock className="w-5 h-5 text-white" />
        </div>
        <span className="font-bold text-xl">BlockVault</span>
      </Link>
      <div className="hidden md:flex items-center gap-5">
        <Link to="/" className="hover:text-accentPurple transition text-sm">Home</Link>
        {user ? (
          <>
            <Link to="/dashboard" className="hover:text-accentPurple transition text-sm">Dashboard</Link>
            <button
              onClick={handleLogout}
              className="text-gray-400 hover:text-red-400 text-sm transition"
            >
              Logout
            </button>
          </>
        ) : (
          <>
            <Link to="/login" className="hover:text-accentPurple transition text-sm">Login</Link>
            <Link to="/signup" className="hover:text-accentPurple transition text-sm">Sign Up</Link>
          </>
        )}
      </div>
    </nav>
  );
}
