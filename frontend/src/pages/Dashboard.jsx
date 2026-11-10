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
    <div className="min-h-[calc(100vh-3.5rem)] bg-bone text-charcoal">
      <div className="max-w-5xl mx-auto px-4 py-8 md:px-6">
        {/* Top Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
          <div>
            <h1 className="font-serif font-bold text-2xl text-charcoal">Your vault</h1>
            <p className="text-sm text-stone mt-1">
              Logged in as <span className="text-charcoal font-medium">{user?.email || user?.name}</span>
            </p>
          </div>
          <button
            onClick={handleOpenAdd}
            className="bg-charcoal text-paper rounded px-4 py-2 text-sm font-medium hover:bg-ash duration-100 flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add Credential
          </button>
        </div>

        {/* Notifications */}
        {successMsg && (
          <div className="mb-6 border border-charcoal/20 bg-charcoal/5 text-charcoal text-sm rounded p-3 flex items-center gap-2">
            <Check className="w-4 h-4" />
            {successMsg}
          </div>
        )}

        {error && (
          <div className="mb-6 border border-accent/40 bg-accent/5 text-accent text-sm rounded p-3 flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError('')} className="text-accent hover:text-accent-hover duration-100">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Search & Category Filter Bar */}
        <div className="bg-paper border border-chalk rounded p-4 mb-6 flex flex-col md:flex-row gap-4 justify-between items-center">
          <div className="relative w-full md:w-96">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-stone" />
            <input
              type="text"
              placeholder="Search website, username, notes..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-paper border border-chalk rounded text-charcoal text-sm placeholder:text-stone/60 focus:border-charcoal focus:outline-none"
            />
          </div>

          <div className="flex flex-wrap gap-2 w-full md:w-auto">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded text-xs font-medium duration-100 ${
                  selectedCategory === cat
                    ? 'bg-charcoal text-paper'
                    : 'border border-chalk text-stone hover:text-charcoal hover:border-charcoal'
                }`}
              >
                {cat}
              </button>
            ))}
            <button
              onClick={fetchCredentials}
              title="Refresh Vault"
              className="border border-chalk text-stone hover:text-charcoal hover:border-charcoal rounded p-2 duration-100"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'motion-safe:animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Credentials List */}
        <div className="bg-paper border border-chalk rounded overflow-hidden">
          <div className="px-6 py-4 border-b border-chalk flex justify-between items-center">
            <h2 className="text-sm font-medium text-charcoal uppercase tracking-wide">Credentials</h2>
            <span className="text-xs text-stone">
              {filteredCredentials.length} item{filteredCredentials.length === 1 ? '' : 's'}
            </span>
          </div>

          {loading ? (
            <div className="py-16 text-center flex flex-col items-center justify-center gap-3">
              <RefreshCw className="w-5 h-5 motion-safe:animate-spin text-stone" />
              <span className="text-stone text-sm">Loading...</span>
            </div>
          ) : filteredCredentials.length === 0 ? (
            <div className="py-16 text-center">
              <p className="text-stone text-sm">
                {searchTerm || selectedCategory !== 'All'
                  ? 'No credentials match your search or filter.'
                  : 'Your vault is empty. Add your first credential above.'}
              </p>
            </div>
          ) : (
            <div>
              {filteredCredentials.map((cred) => {
                const isPasswordRevealed = !!showPasswordMap[cred.id];
                const isPwCopied = !!copiedMap[`pw-${cred.id}`];
                const isUserCopied = !!copiedMap[`u-${cred.id}`];

                return (
                  <div
                    key={cred.id}
                    className="px-6 py-5 border-b border-chalk last:border-b-0 hover:bg-bone/50 duration-100 flex flex-col md:flex-row md:items-center justify-between gap-4"
                  >
                    {/* Left: Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3">
                        <button
                          onClick={() => handleToggleFavorite(cred)}
                          className={`duration-100 ${
                            cred.is_favorite
                              ? 'text-accent'
                              : 'text-stone hover:text-charcoal'
                          }`}
                          title={cred.is_favorite ? 'Favorited' : 'Add to favorites'}
                        >
                          <Star className={`w-4 h-4 ${cred.is_favorite ? 'fill-accent' : ''}`} />
                        </button>

                        <h3 className="font-medium text-charcoal truncate">{cred.website}</h3>

                        {cred.website_url && (
                          <a
                            href={cred.website_url.startsWith('http') ? cred.website_url : `https://${cred.website_url}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-stone hover:text-charcoal duration-100"
                            title="Open URL"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>
                        )}

                        <span className="text-xs border border-chalk text-stone rounded px-2 py-0.5">
                          {cred.category || 'General'}
                        </span>
                      </div>

                      {/* Username & Password */}
                      <div className="mt-3 flex flex-wrap items-center gap-3 text-sm">
                        <div className="flex items-center gap-2 bg-bone px-3 py-1.5 rounded border border-chalk">
                          <span className="text-stone text-xs">User:</span>
                          <span className="font-mono text-sm text-charcoal">{cred.username}</span>
                          <button
                            onClick={() => handleCopy(cred.username, `u-${cred.id}`)}
                            className="text-stone hover:text-charcoal duration-100 ml-1"
                            title="Copy Username"
                          >
                            {isUserCopied ? (
                              <Check className="w-3.5 h-3.5 text-charcoal" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>

                        <div className="flex items-center gap-2 bg-bone px-3 py-1.5 rounded border border-chalk">
                          <span className="text-stone text-xs">Password:</span>
                          <span className="font-mono text-sm text-charcoal">
                            {isPasswordRevealed ? cred.password : '••••••••••••'}
                          </span>
                          <button
                            onClick={() => toggleReveal(cred.id)}
                            className="text-stone hover:text-charcoal duration-100 ml-1"
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
                            className="text-stone hover:text-charcoal duration-100"
                            title="Copy Password"
                          >
                            {isPwCopied ? (
                              <Check className="w-3.5 h-3.5 text-charcoal" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </div>

                      {cred.notes && (
                        <p className="mt-2 text-xs text-stone italic line-clamp-1">
                          Note: {cred.notes.replace('[FAVORITE]', '').trim()}
                        </p>
                      )}
                    </div>

                    {/* Right: Actions */}
                    <div className="flex items-center gap-1 self-end md:self-center">
                      <button
                        onClick={() => handleOpenEdit(cred)}
                        className="p-2 text-stone hover:text-charcoal duration-100"
                        title="Edit Credential"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setDeleteTarget(cred)}
                        className="p-2 text-stone hover:text-accent duration-100"
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
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-charcoal/60">
          <div className="bg-paper border border-chalk w-full max-w-lg rounded p-6">
            <div className="flex justify-between items-center mb-5 pb-3 border-b border-chalk">
              <h3 className="text-lg font-serif font-bold text-charcoal">
                {editingCred ? 'Edit Credential' : 'Add New Credential'}
              </h3>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-stone hover:text-charcoal duration-100"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {modalError && (
              <div className="mb-4 border border-accent/40 bg-accent/5 text-accent text-sm rounded p-3">
                {modalError}
              </div>
            )}

            <form onSubmit={handleSaveModal} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-stone uppercase tracking-wide mb-1.5">
                  Website / Service Name *
                </label>
                <input
                  type="text"
                  placeholder="e.g. GitHub, Google, Netflix"
                  required
                  value={modalForm.website}
                  onChange={(e) => setModalForm({ ...modalForm, website: e.target.value })}
                  className="w-full px-3 py-2 bg-paper border border-chalk rounded text-charcoal text-sm placeholder:text-stone/60 focus:border-charcoal focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-stone uppercase tracking-wide mb-1.5">
                  Website URL (Optional)
                </label>
                <input
                  type="text"
                  placeholder="https://example.com"
                  value={modalForm.website_url}
                  onChange={(e) => setModalForm({ ...modalForm, website_url: e.target.value })}
                  className="w-full px-3 py-2 bg-paper border border-chalk rounded text-charcoal text-sm placeholder:text-stone/60 focus:border-charcoal focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-stone uppercase tracking-wide mb-1.5">
                    Username / Email *
                  </label>
                  <input
                    type="text"
                    placeholder="user@example.com"
                    required
                    value={modalForm.username}
                    onChange={(e) => setModalForm({ ...modalForm, username: e.target.value })}
                    className="w-full px-3 py-2 bg-paper border border-chalk rounded text-charcoal text-sm placeholder:text-stone/60 focus:border-charcoal focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-stone uppercase tracking-wide mb-1.5">
                    Category
                  </label>
                  <select
                    value={modalForm.category}
                    onChange={(e) => setModalForm({ ...modalForm, category: e.target.value })}
                    className="w-full px-3 py-2 bg-paper border border-chalk rounded text-charcoal text-sm focus:border-charcoal focus:outline-none"
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
                <label className="block text-xs font-medium text-stone uppercase tracking-wide mb-1.5">
                  Password *
                </label>
                <input
                  type="password"
                  placeholder="Enter credential password"
                  required
                  value={modalForm.password}
                  onChange={(e) => setModalForm({ ...modalForm, password: e.target.value })}
                  className="w-full px-3 py-2 bg-paper border border-chalk rounded text-charcoal text-sm placeholder:text-stone/60 focus:border-charcoal focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-stone uppercase tracking-wide mb-1.5">
                  Notes (Optional)
                </label>
                <textarea
                  rows={2}
                  placeholder="Additional recovery keys, 2FA notes, etc."
                  value={modalForm.notes}
                  onChange={(e) => setModalForm({ ...modalForm, notes: e.target.value })}
                  className="w-full px-3 py-2 bg-paper border border-chalk rounded text-charcoal text-sm placeholder:text-stone/60 focus:border-charcoal focus:outline-none"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="modalFav"
                  checked={modalForm.is_favorite}
                  onChange={(e) => setModalForm({ ...modalForm, is_favorite: e.target.checked })}
                  className="w-4 h-4 rounded accent-[#1C1C1E]"
                />
                <label htmlFor="modalFav" className="text-sm text-charcoal cursor-pointer">
                  Mark as Favorite
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-chalk">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  disabled={modalSaving}
                  className="border border-chalk text-charcoal rounded px-4 py-2 text-sm hover:border-charcoal duration-100"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={modalSaving}
                  className="bg-charcoal text-paper rounded px-5 py-2 text-sm font-medium hover:bg-ash duration-100 disabled:opacity-50"
                >
                  {modalSaving ? 'Saving...' : editingCred ? 'Update Entry' : 'Save to Vault'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-charcoal/60">
          <div className="bg-paper border border-chalk w-full max-w-sm rounded p-6">
            <h3 className="text-lg font-serif font-bold text-charcoal mb-2">Delete Credential?</h3>
            <p className="text-sm text-stone mb-6">
              Are you sure you want to delete the credentials for{' '}
              <span className="font-medium text-charcoal">{deleteTarget.website}</span>? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteTarget(null)}
                disabled={deleting}
                className="border border-chalk text-charcoal rounded px-4 py-2 text-sm hover:border-charcoal duration-100"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteConfirm}
                disabled={deleting}
                className="bg-accent text-paper rounded px-4 py-2 text-sm font-medium hover:bg-accent-hover duration-100 disabled:opacity-50"
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
