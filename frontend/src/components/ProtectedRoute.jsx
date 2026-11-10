import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const ProtectedRoute = ({ children }) => {
  const { user, token, loading } = useAuth();

  // Wait for authentication verification
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-bone">
        <p className="text-stone font-sans text-sm">Verifying...</p>
      </div>
    );
  }

  // Redirect unauthenticated users
  if (!user || !token) {
    return <Navigate to="/login" replace />;
  }

  return children;
};

export default ProtectedRoute;
