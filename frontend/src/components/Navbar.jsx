import React from 'react';
import { Link } from 'react-router-dom';
import { Lock } from 'lucide-react';

export default function Navbar() {
  return (
    <nav className="bg-primary text-white flex items-center justify-between px-6 py-3 shadow-glass">
      <div className="flex items-center gap-2">
        <div className="w-8 h-8 bg-gradient-to-br from-accentPurple to-accentBlue rounded-md flex items-center justify-center">
          <Lock className="w-5 h-5 text-white" />
        </div>
        <span className="font-bold text-xl">BlockVault</span>
      </div>
      <div className="hidden md:flex gap-4">
        <Link to="/" className="hover:text-accentPurple transition">Home</Link>
        <Link to="/dashboard" className="hover:text-accentPurple transition">Dashboard</Link>
        <Link to="/login" className="hover:text-accentPurple transition">Login</Link>
        <Link to="/signup" className="hover:text-accentPurple transition">Sign Up</Link>
      </div>
    </nav>
  );
}

