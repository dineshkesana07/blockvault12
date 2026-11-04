
import React, {
  createContext,
  useState,
  useContext,
  useEffect
} from 'react';

import { authAPI } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {

  const [user, setUser] = useState(() => {
    try {
      const savedUser = localStorage.getItem('blockvault_user');
      return savedUser ? JSON.parse(savedUser) : null;
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState(
    () => localStorage.getItem('blockvault_token') || null
  );

  const [loading, setLoading] = useState(
    () => !!localStorage.getItem('blockvault_token')
  );

  // Verify session with backend whenever token changes
  useEffect(() => {
    let active = true;

    const verifySession = async () => {

      if (!token) {
        setUser(null);
        setLoading(false);
        return;
      }

      setLoading(true);

      try {
        const res = await authAPI.getMe();

        if (active && res.data) {
          setUser(res.data);
          localStorage.setItem(
            'blockvault_user',
            JSON.stringify(res.data)
          );
        }

      } catch (error) {

        if (active) {
          setUser(null);
          setToken(null);

          localStorage.removeItem('blockvault_token');
          localStorage.removeItem('blockvault_user');

          sessionStorage.removeItem('blockvault_token');
          sessionStorage.removeItem('blockvault_user');
        }

      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    verifySession();

    return () => {
      active = false;
    };

  }, [token]);

  // Login
  const login = (userData, authToken) => {

    if (!authToken) {
      return;
    }

    setUser(userData || null);
    setToken(authToken);
    setLoading(false);

    localStorage.setItem('blockvault_token', authToken);

    if (userData) {
      localStorage.setItem(
        'blockvault_user',
        JSON.stringify(userData)
      );
    }
  };

  // Logout
  const logout = async () => {

    try {
      await authAPI.logout();
    } catch (error) {
      console.error('Logout request failed:', error);
    } finally {

      setUser(null);
      setToken(null);
      setLoading(false);

      localStorage.removeItem('blockvault_token');
      localStorage.removeItem('blockvault_user');

      sessionStorage.removeItem('blockvault_token');
      sessionStorage.removeItem('blockvault_user');
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        isAuthenticated: !!user && !!token,
        login,
        logout
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
