import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import { vaultAPI } from '../services/api';

export default function Dashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchCredentials();
  }, []);

  const fetchCredentials = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await vaultAPI.getAll();
      if (res.data && Array.isArray(res.data.credentials)) {
        setCredentials(res.data.credentials);
      } else if (Array.isArray(res.data)) {
        setCredentials(res.data);
      }
    } catch (err) {
      if (err.response?.status === 401) {
        logout();
        navigate('/login');
      } else {
        setError(err.response?.data?.error || 'Failed to load vault credentials.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  return (
    <div className="min-h-screen bg-black text-white p-8">
      <div className="max-w-4xl mx-auto">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-4xl">Welcome, {user?.name || 'User'}!</h1>
          <button
            onClick={handleLogout}
            className="bg-red-500 hover:bg-red-600 transition text-white px-4 py-2 rounded font-semibold"
          >
            Logout
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-900/50 border border-red-500 text-red-200 rounded">
            {error}
          </div>
        )}

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 shadow-glass">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-bold">Your Encrypted Vault</h2>
            <span className="text-sm text-gray-400">
              {credentials.length} credential{credentials.length === 1 ? '' : 's'} stored
            </span>
          </div>

          {loading ? (
            <p className="text-gray-400 py-4 text-center">Loading vault credentials...</p>
          ) : credentials.length === 0 ? (
            <p className="text-gray-400 py-4 text-center">
              Your vault is currently empty. Use the API or add credentials to get started.
            </p>
          ) : (
            <div className="divide-y divide-gray-800">
              {credentials.map((cred) => (
                <div key={cred.id} className="py-3 flex justify-between items-center">
                  <div>
                    <h3 className="font-semibold text-white">{cred.website}</h3>
                    <p className="text-sm text-gray-400">{cred.username}</p>
                  </div>
                  <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">
                    {cred.category || 'General'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
