import axios from 'axios';

// Centralized API Base URL configured via import.meta.env.VITE_API_URL
// If not specified, falls back to empty string (relative paths / same-origin proxy)
const rawUrl = (import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || '').trim();
export const API_BASE_URL = rawUrl.replace(/\/+$/, '');

// Create Axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000,
});

// Helper to resolve API path whether API_BASE_URL includes '/api' or not
export const resolveApiPath = (path) => {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  if (API_BASE_URL.endsWith('/api')) {
    return cleanPath.startsWith('/api') ? cleanPath.substring(4) : cleanPath;
  }
  return cleanPath.startsWith('/api') ? cleanPath : `/api${cleanPath}`;
};

// Request interceptor: attach JWT Bearer token from localStorage or sessionStorage
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('blockvault_token') || sessionStorage.getItem('blockvault_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: handle 401 unauthorized / expired session
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('blockvault_token');
      sessionStorage.removeItem('blockvault_token');
      localStorage.removeItem('blockvault_user');
      sessionStorage.removeItem('blockvault_user');
    }
    return Promise.reject(error);
  }
);

// Authentication API methods
export const authAPI = {
  register: (name, email, masterPassword) =>
    api.post(resolveApiPath('/api/auth/register'), {
      name,
      email,
      master_password: masterPassword,
    }),

  login: (email, masterPassword) =>
    api.post(resolveApiPath('/api/auth/login'), {
      email,
      master_password: masterPassword,
    }),

  logout: () =>
    api.post(resolveApiPath('/api/auth/logout')),

  getMe: () =>
    api.get(resolveApiPath('/api/auth/me')),
};

// Vault API methods
export const vaultAPI = {
  getAll: (params) =>
    api.get(resolveApiPath('/api/vault'), { params }),

  getById: (id) =>
    api.get(resolveApiPath(`/api/vault/${id}`)),

  create: (credentialData) =>
    api.post(resolveApiPath('/api/vault'), credentialData),

  update: (id, credentialData) =>
    api.put(resolveApiPath(`/api/vault/${id}`), credentialData),

  delete: (id) =>
    api.delete(resolveApiPath(`/api/vault/${id}`)),

  setFavorite: (id, isFavorite = true) =>
    api.post(resolveApiPath(`/api/vault/${id}/favorite`), {
      is_favorite: isFavorite,
    }),
};

// Health Check API method
export const healthAPI = {
  check: () =>
    api.get(resolveApiPath('/api/health')),
};

export default api;

