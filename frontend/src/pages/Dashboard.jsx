import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import { vaultAPI } from '../services/api';
import {
  Plus,
  Trash2,
  Edit2,
  Star,
  Eye,
  EyeOff,
  Copy,
  Check,
  Search,
  ExternalLink,
  Lock,
  X,
  RefreshCw,
} from 'lucide-react';

export default function Dashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // Search & Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');

  // UI interaction state
  const [showPasswordMap, setShowPasswordMap] = useState({});
  const [copiedMap, setCopiedMap] = useState({});

  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingCred, setEditingCred] = useState(null);
  const [modalForm, setModalForm] = useState({
    website: '',
    website_url: '',
    username: '',
    password: '',
    category: 'General',
    notes: '',
    is_favorite: false,
  });
  const [modalSaving, setModalSaving] = useState(false);
  const [modalError, setModalError] = useState('');

  // Delete confirmation modal
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const categories = ['All', 'General', 'Work', 'Finance', 'Entertainment', 'Social', 'Personal'];

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
      } else {
        setCredentials([]);
      }
    } catch (err) {
      if (err.response?.status === 401) {
        logout();
        navigate('/login');
      } else {
        setError(err.response?.data?.error || 'Failed to load credentials from vault.');
      }
    } finally {
      setLoading(false);
    }
  };

  const showNotification = (msg) => {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(''), 3000);
  };

  // Toggle Reveal Password
  const toggleReveal = (id) => {
    setShowPasswordMap((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  // Copy to clipboard with visual feedback
  const handleCopy = (text, key) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedMap((prev) => ({ ...prev, [key]: true }));
    setTimeout(() => {
      setCopiedMap((prev) => ({ ...prev, [key]: false }));
    }, 2000);
  };

  // Toggle Favorite
  const handleToggleFavorite = async (cred) => {
    const nextState = !cred.is_favorite;
    try {
      await vaultAPI.setFavorite(cred.id, nextState);
      setCredentials((prev) =>
        prev.map((item) => (item.id === cred.id ? { ...item, is_favorite: nextState } : item))
      );
      showNotification(nextState ? 'Added to favorites.' : 'Removed from favorites.');
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to update favorite status.');
    }
  };

  // Open Modal for Add
  const handleOpenAdd = () => {
    setEditingCred(null);
    setModalForm({
      website: '',
      website_url: '',
      username: '',
      password: '',
      category: 'General',
      notes: '',
      is_favorite: false,
    });
    setModalError('');
    setIsModalOpen(true);
  };

  // Open Modal for Edit
  const handleOpenEdit = (cred) => {
    setEditingCred(cred);
    setModalForm({
      website: cred.website || '',
      website_url: cred.website_url || '',
      username: cred.username || '',
      password: cred.password || '',
      category: cred.category || 'General',
      notes: cred.notes || '',
      is_favorite: !!cred.is_favorite,
    });
    setModalError('');
    setIsModalOpen(true);
  };

  // Save Modal (Create or Update)
  const handleSaveModal = async (e) => {
    e.preventDefault();
    if (!modalForm.website.trim() || !modalForm.username.trim() || !modalForm.password) {
      setModalError('Please fill in website name, username, and password.');
      return;
    }

    setModalSaving(true);
    setModalError('');

    try {
      if (editingCred) {
        await vaultAPI.update(editingCred.id, modalForm);
        showNotification('Credential updated successfully.');
      } else {
        await vaultAPI.create(modalForm);
        showNotification('Credential saved to vault.');
      }
      setIsModalOpen(false);
      fetchCredentials();
    } catch (err) {
      setModalError(err.response?.data?.error || 'Failed to save credential.');
    } finally {
      setModalSaving(false);
    }
  };

  // Delete Credential
  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await vaultAPI.delete(deleteTarget.id);
      setCredentials((prev) => prev.filter((c) => c.id !== deleteTarget.id));
      showNotification('Credential removed from vault.');
      setDeleteTarget(null);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to delete credential.');
    } finally {
      setDeleting(false);
    }
  };

  // Filter & Search Logic
  const filteredCredentials = credentials.filter((cred) => {
    const matchesCategory =
      selectedCategory === 'All' ||
      (cred.category && cred.category.toLowerCase() === selectedCategory.toLowerCase());
    const matchesSearch =
      (cred.website && cred.website.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (cred.username && cred.username.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (cred.notes && cred.notes.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="min-h-screen bg-black text-white p-6 md:p-10">
      <div className="max-w-6xl mx-auto">
        {/* Top Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
          <div>
            <h1 className="text-3xl md:text-4xl font-extrabold text-white flex items-center gap-3">
              <span className="p-2 bg-gradient-to-br from-accentPurple to-accentBlue rounded-lg">
                <Lock className="w-7 h-7 text-white" />
              </span>
              BlockVault
            </h1>
            <p className="text-gray-400 mt-1">
              Logged in as <span className="text-accentBlue font-medium">{user?.email || user?.name}</span>
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleOpenAdd}
              className="bg-accentPurple hover:bg-accentPurple/80 transition text-white px-4 py-2.5 rounded-lg font-semibold flex items-center gap-2 shadow-glass"
            >
              <Plus className="w-5 h-5" />
              Add Credential
            </button>
          </div>
        </div>

        {/* Notifications */}
        {successMsg && (
          <div className="mb-6 p-4 bg-green-950/70 border border-green-500 text-green-300 text-sm rounded-lg flex items-center gap-2">
            <Check className="w-4 h-4 text-green-400" />
            {successMsg}
          </div>
        )}

        {error && (
          <div className="mb-6 p-4 bg-red-950/70 border border-red-500 text-red-300 text-sm rounded-lg flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError('')} className="text-red-400 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Search & Category Filter Bar */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-6 shadow-glass flex flex-col md:flex-row gap-4 justify-between items-center">
          <div className="relative w-full md:w-96">
            <Search className="absolute left-3.5 top-3 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search website, username, notes..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:border-accentPurple outline-none"
            />
          </div>

          <div className="flex flex-wrap gap-2 w-full md:w-auto">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  selectedCategory === cat
                    ? 'bg-accentPurple text-white'
                    : 'bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700'
                }`}
              >
                {cat}
              </button>
            ))}
            <button
              onClick={fetchCredentials}
              title="Refresh Vault"
              className="p-2 bg-gray-800 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700 transition"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Credentials Grid / List */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden shadow-glass">
          <div className="px-6 py-4 border-b border-gray-800 flex justify-between items-center">
            <h2 className="text-lg font-bold text-white">Your Credentials</h2>
            <span className="text-xs text-gray-400 bg-gray-800 px-2.5 py-1 rounded-full">
              {filteredCredentials.length} item{filteredCredentials.length === 1 ? '' : 's'}
            </span>
          </div>

          {loading ? (
            <div className="py-16 text-center text-gray-400 flex flex-col items-center justify-center gap-3">
              <RefreshCw className="w-6 h-6 animate-spin text-accentPurple" />
              <span>Fetching encrypted credentials from Render backend...</span>
            </div>
          ) : filteredCredentials.length === 0 ? (
            <div className="py-16 text-center text-gray-500">
              <p className="text-lg font-semibold text-gray-400">No credentials found</p>
              <p className="text-sm mt-1">
                {searchTerm || selectedCategory !== 'All'
                  ? 'Try adjusting your search query or filter.'
                  : 'Your vault is currently empty. Add your first login above!'}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-gray-800">
              {filteredCredentials.map((cred) => {
                const isPasswordRevealed = !!showPasswordMap[cred.id];
                const isPwCopied = !!copiedMap[`pw-${cred.id}`];
                const isUserCopied = !!copiedMap[`u-${cred.id}`];

                return (
                  <div
                    key={cred.id}
                    className="p-5 hover:bg-gray-800/40 transition flex flex-col md:flex-row md:items-center justify-between gap-4"
                  >
                    {/* Left: Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3">
                        <button
                          onClick={() => handleToggleFavorite(cred)}
                          className={`transition ${
                            cred.is_favorite
                              ? 'text-yellow-400 hover:text-yellow-500'
                              : 'text-gray-600 hover:text-gray-400'
                          }`}
                          title={cred.is_favorite ? 'Favorited' : 'Add to favorites'}
                        >
                          <Star className={`w-5 h-5 ${cred.is_favorite ? 'fill-yellow-400' : ''}`} />
                        </button>

                        <h3 className="font-bold text-lg text-white truncate">{cred.website}</h3>

                        {cred.website_url && (
                          <a
                            href={cred.website_url.startsWith('http') ? cred.website_url : `https://${cred.website_url}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-gray-500 hover:text-accentBlue transition"
                            title="Open URL"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        )}

                        <span className="text-xs bg-gray-800 border border-gray-700 text-gray-300 px-2 py-0.5 rounded">
                          {cred.category || 'General'}
                        </span>
                      </div>

                      {/* Username & Password */}
                      <div className="mt-3 flex flex-wrap items-center gap-4 text-sm">
                        <div className="flex items-center gap-2 bg-gray-950 px-3 py-1.5 rounded-lg border border-gray-800">
                          <span className="text-gray-400 text-xs">User:</span>
                          <span className="font-mono text-gray-200">{cred.username}</span>
                          <button
                            onClick={() => handleCopy(cred.username, `u-${cred.id}`)}
                            className="text-gray-400 hover:text-white transition ml-1"
                            title="Copy Username"
                          >
                            {isUserCopied ? (
                              <Check className="w-3.5 h-3.5 text-green-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>

                        <div className="flex items-center gap-2 bg-gray-950 px-3 py-1.5 rounded-lg border border-gray-800">
                          <span className="text-gray-400 text-xs">Password:</span>
                          <span className="font-mono text-gray-200">
                            {isPasswordRevealed ? cred.password : '••••••••••••'}
                          </span>
                          <button
                            onClick={() => toggleReveal(cred.id)}
                            className="text-gray-400 hover:text-white transition ml-1"
                            title={isPasswordRevealed ? 'Hide Password' : 'Show Password'}
                          >
                            {isPasswordRevealed ? (
                              <EyeOff className="w-3.5 h-3.5" />
                            ) : (
                              <Eye className="w-3.5 h-3.5" />
                            )}
                          </button>
                          <button
                            onClick={() => handleCopy(cred.password, `pw-${cred.id}`)}
                            className="text-gray-400 hover:text-white transition"
                            title="Copy Password"
                          >
                            {isPwCopied ? (
                              <Check className="w-3.5 h-3.5 text-green-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </div>

                      {cred.notes && (
                        <p className="mt-2 text-xs text-gray-400 line-clamp-1 italic">
                          Note: {cred.notes.replace('[FAVORITE]', '').trim()}
                        </p>
                      )}
                    </div>

                    {/* Right: Actions */}
                    <div className="flex items-center gap-2 self-end md:self-center">
                      <button
                        onClick={() => handleOpenEdit(cred)}
                        className="p-2 text-gray-400 hover:text-accentBlue hover:bg-gray-800 rounded-lg transition"
                        title="Edit Credential"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setDeleteTarget(cred)}
                        className="p-2 text-gray-400 hover:text-red-400 hover:bg-gray-800 rounded-lg transition"
                        title="Delete Credential"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Add / Edit Credential Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-gray-900 border border-gray-700 w-full max-w-lg rounded-xl shadow-2xl p-6">
            <div className="flex justify-between items-center mb-5 pb-3 border-b border-gray-800">
              <h3 className="text-xl font-bold text-white">
                {editingCred ? 'Edit Credential' : 'Add New Credential'}
              </h3>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-gray-400 hover:text-white transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {modalError && (
              <div className="mb-4 p-3 bg-red-950/70 border border-red-500 text-red-300 text-sm rounded-lg">
                {modalError}
              </div>
            )}

            <form onSubmit={handleSaveModal} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-300 uppercase mb-1.5">
                  Website / Service Name *
                </label>
                <input
                  type="text"
                  placeholder="e.g. GitHub, Google, Netflix"
                  required
                  value={modalForm.website}
                  onChange={(e) => setModalForm({ ...modalForm, website: e.target.value })}
                  className="w-full px-3.5 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:border-accentPurple outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 uppercase mb-1.5">
                  Website URL (Optional)
                </label>
                <input
                  type="text"
                  placeholder="https://example.com"
                  value={modalForm.website_url}
                  onChange={(e) => setModalForm({ ...modalForm, website_url: e.target.value })}
                  className="w-full px-3.5 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:border-accentPurple outline-none"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 uppercase mb-1.5">
                    Username / Email *
                  </label>
                  <input
                    type="text"
                    placeholder="user@example.com"
                    required
                    value={modalForm.username}
                    onChange={(e) => setModalForm({ ...modalForm, username: e.target.value })}
                    className="w-full px-3.5 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:border-accentPurple outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-300 uppercase mb-1.5">
                    Category
                  </label>
                  <select
                    value={modalForm.category}
                    onChange={(e) => setModalForm({ ...modalForm, category: e.target.value })}
                    className="w-full px-3.5 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:border-accentPurple outline-none"
                  >
                    <option value="General">General</option>
                    <option value="Work">Work</option>
                    <option value="Finance">Finance</option>
                    <option value="Entertainment">Entertainment</option>
                    <option value="Social">Social</option>
                    <option value="Personal">Personal</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 uppercase mb-1.5">
                  Password *
                </label>
                <input
                  type="password"
                  placeholder="Enter credential password"
                  required
                  value={modalForm.password}
                  onChange={(e) => setModalForm({ ...modalForm, password: e.target.value })}
                  className="w-full px-3.5 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:border-accentPurple outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 uppercase mb-1.5">
                  Notes (Optional)
                </label>
                <textarea
                  rows={2}
                  placeholder="Additional recovery keys, 2FA notes, etc."
                  value={modalForm.notes}
                  onChange={(e) => setModalForm({ ...modalForm, notes: e.target.value })}
                  className="w-full px-3.5 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:border-accentPurple outline-none"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="modalFav"
                  checked={modalForm.is_favorite}
                  onChange={(e) => setModalForm({ ...modalForm, is_favorite: e.target.checked })}
                  className="w-4 h-4 rounded text-accentPurple bg-gray-800 border-gray-700 focus:ring-accentPurple"
                />
                <label htmlFor="modalFav" className="text-sm text-gray-300 cursor-pointer">
                  Mark as Favorite
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-gray-800">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  disabled={modalSaving}
                  className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={modalSaving}
                  className="px-5 py-2 bg-accentPurple hover:bg-accentPurple/80 text-white rounded-lg text-sm font-semibold transition disabled:opacity-50"
                >
                  {modalSaving ? 'Encrypting & Saving...' : editingCred ? 'Update Entry' : 'Save to Vault'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-gray-900 border border-gray-700 w-full max-w-md rounded-xl p-6 shadow-2xl">
            <h3 className="text-lg font-bold text-white mb-2">Delete Credential?</h3>
            <p className="text-sm text-gray-400 mb-6">
              Are you sure you want to delete the credentials for{' '}
              <span className="font-semibold text-white">{deleteTarget.website}</span>? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteTarget(null)}
                disabled={deleting}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteConfirm}
                disabled={deleting}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-semibold transition disabled:opacity-50"
              >
                {deleting ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
