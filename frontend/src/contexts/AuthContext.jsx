import React, { createContext, useState, useContext, useEffect } from 'react';
import { authAPI } from '../services/api';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    try {
      const savedUser = localStorage.getItem('blockvault_user');
      return savedUser ? JSON.parse(savedUser) : null;
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState(() => {
    return localStorage.getItem('blockvault_token') || null;
  });

  const [loading, setLoading] = useState(false);

  // Validate or refresh session on mount if token exists
  useEffect(() => {
    if (token) {
      authAPI.getMe()
        .then((res) => {
          if (res.data) {
            setUser(res.data);
            localStorage.setItem('blockvault_user', JSON.stringify(res.data));
          }
        })
        .catch(() => {
          // Token expired or invalid
          logout();
        });
    }
  }, [token]);

  const login = (userData, authToken) => {
    if (typeof userData === 'object' && userData !== null) {
      setUser(userData);
      localStorage.setItem('blockvault_user', JSON.stringify(userData));
    }
    if (authToken) {
      setToken(authToken);
      localStorage.setItem('blockvault_token', authToken);
    }
  };

  const logout = async () => {
    try {
      await authAPI.logout();
    } catch {
      // Ignore network errors on logout
    } finally {
      setUser(null);
      setToken(null);
      localStorage.removeItem('blockvault_token');
      sessionStorage.removeItem('blockvault_token');
      localStorage.removeItem('blockvault_user');
      sessionStorage.removeItem('blockvault_user');
    }
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, isAuthenticated: !!token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
