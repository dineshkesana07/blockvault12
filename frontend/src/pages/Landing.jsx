import React from 'react';
import { Link } from 'react-router-dom';

export default function Landing() {
  return (
    <div className="min-h-screen bg-black text-white flex flex-col items-center">
      {/* Hero Section */}
      <section className="w-full flex flex-col items-center justify-center py-24 bg-gradient-to-b from-red-800 via-black to-green-900">
        <h1 className="text-5xl md:text-6xl font-extrabold mb-4" style={{ color: '#FF0000' }}>
          BlockVault
        </h1>
        <p className="text-xl md:text-2xl mb-8" style={{ color: '#00FF00' }}>
          Your Digital Life. One Secure Vault.
        </p>
        <div className="flex gap-4">
          <Link
            to="/signup"
            className="px-6 py-3 bg-white text-black rounded-md font-semibold hover:bg-gray-200 transition"
          >
            Get Started
          </Link>
          <Link
            to="/login"
            className="px-6 py-3 border border-white rounded-md font-semibold hover:bg-white hover:text-black transition"
          >
            Login
          </Link>
        </div>
      </section>

      {/* Features */}
      <section className="max-w-5xl w-full grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 p-8">
        {["Local Storage", "Master Password", "Secure Encryption", "Organized Credentials"].map((title) => (
          <div key={title} className="bg-gray-900 p-6 rounded-lg shadow-glass border border-gray-700">
            <h3 className="text-2xl font-bold mb-2" style={{ color: '#FF0000' }}>{title}</h3>
            <p className="text-gray-300" style={{ color: '#00FF00' }}>Lorem ipsum dolor sit amet.</p>
          </div>
        ))}
      </section>
    </div>
  );
}


