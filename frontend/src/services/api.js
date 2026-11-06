import axios from 'axios';

// Centralized API Base URL configured via Vite environment variable VITE_API_BASE_URL
// Defaults to the deployed Render backend: https://blockvault12.onrender.com
const envBaseUrl = (
  import.meta.env.VITE_API_BASE_URL ||
  import.meta.env.VITE_API_URL ||
  'http://localhost:10000'
).trim();

// Strip trailing slashes to ensure uniform path resolution
export const API_BASE_URL = envBaseUrl.replace(/\/+$/, '');

// Create Axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000,
});

/**
 * Normalizes endpoint paths to prevent duplicate '/api' prefixes:
 * - If API_BASE_URL already ends with '/api' (e.g. 'https://blockvault12.onrender.com/api'),
 *   calling resolveApiPath('/api/vault') strips '/api' -> '/vault'.
 * - If API_BASE_URL does not end with '/api' (e.g. 'https://blockvault12.onrender.com'),
 *   calling resolveApiPath('/api/vault') returns '/api/vault'.
 */
export const resolveApiPath = (path) => {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  if (API_BASE_URL.endsWith('/api')) {
    return cleanPath.startsWith('/api') ? cleanPath.substring(4) : cleanPath;
  }
  return cleanPath.startsWith('/api') ? cleanPath : `/api${cleanPath}`;
};

// Request interceptor: attach JWT Bearer token from storage without logging sensitive material
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

// Response interceptor: automatically invalidate expired sessions on HTTP 401
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
  signup: (name, email, masterPassword) =>
    api.post(resolveApiPath('/api/auth/signup'), {
      name,
      email,
      master_password: masterPassword,
    }),

  verifyOtp: (email, otp, masterPassword) =>
    api.post(resolveApiPath('/api/auth/verify-otp'), {
      email,
      otp,
      master_password: masterPassword,
    }),

  resendOtp: (email) =>
    api.post(resolveApiPath('/api/auth/resend-otp'), { email }),

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
