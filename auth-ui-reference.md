# Clique API Authentication Reference for UI Development

## Overview
This document provides complete authentication specifications for building UI components that integrate with the Clique API. The system supports JWT-based authentication with role-based access control for three user types: Creator, Company, and Admin.

## Base Configuration
```typescript
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
const AUTH_ENDPOINTS = {
  signup: '/auth/signup',
  login: '/auth/login',
  logout: '/auth/logout',
  refresh: '/auth/refresh',
  me: '/auth/me',
  passwordReset: '/auth/password-reset',
  passwordResetConfirm: '/auth/password-reset/confirm'
}
```

## Authentication Flow

### 1. User Registration (`POST /auth/signup`)

**Request Body:**
```typescript
interface SignupRequest {
  email: string;
  username: string;
  password: string;
  firstName: string;
  lastName: string;
  userType: 'CREATOR' | 'COMPANY' | 'ADMIN';
  
  // Optional fields for Creator
  bio?: string;
  niche?: string[];
  
  // Optional fields for Company
  companyName?: string;
  industry?: string;
  website?: string;
  description?: string;
}
```

**Validation Rules:**
- **Email:** Valid email format
- **Username:** 
  - Minimum 3 characters
  - Only letters, numbers, underscores, hyphens
  - Converted to lowercase
- **Password:** 
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter  
  - At least one digit
- **Website:** Must start with http:// or https://

**Response:** `TokenResponse` (see below)

### 2. User Login (`POST /auth/login`)

**Request Body:**
```typescript
interface LoginRequest {
  email: string;
  password: string;
}
```

**Response:** `TokenResponse`

### 3. Token Response Structure
```typescript
interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number; // seconds (3600 = 1 hour)
  refresh_token?: string;
  user: UserResponse;
}
```

### 4. User Response Structure
```typescript
interface UserResponse {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  userType: 'CREATOR' | 'COMPANY' | 'ADMIN';
  status: 'ACTIVE' | 'SUSPENDED' | 'PENDING_VERIFICATION' | 'DEACTIVATED';
  isVerified: boolean;
  avatar?: string;
  phone?: string;
  location?: string;
  createdAt: string; // ISO date string
  profile?: CreatorProfile | CompanyProfile | AdminProfile;
  roles?: Role[];
}

interface CreatorProfile {
  role: 'CREATOR';
  bio?: string;
  niche: string[];
  totalFollowers: number;
  avgEngagement: number;
  isVerified: boolean;
  plan: 'FREE' | 'BASIC' | 'PRO';
}

interface CompanyProfile {
  role: 'COMPANY';
  companyName: string;
  industry: string;
  website?: string;
  description?: string;
  plan: 'FREE' | 'BASIC' | 'PRO';
}

interface AdminProfile {
  role: 'SUPER_ADMIN' | 'ADMIN' | 'MODERATOR';
}

interface Role {
  id: string;
  name: string;
  description?: string;
}
```

## Authentication Headers
```typescript
const authHeaders = {
  'Authorization': `Bearer ${accessToken}`,
  'Content-Type': 'application/json'
}
```

## Token Management

### 1. Get Current User (`GET /auth/me`)
**Headers:** Authorization: Bearer {access_token}
**Response:** `UserResponse`

### 2. Refresh Token (`POST /auth/refresh`)
**Headers:** Authorization: Bearer {refresh_token}
**Response:** `TokenResponse` (without refresh_token)

### 3. Logout (`POST /auth/logout`)
**Headers:** Authorization: Bearer {access_token}
**Response:** `{ message: "Successfully logged out" }`

## Password Reset

### 1. Request Reset (`POST /auth/password-reset`)
**Request Body:**
```typescript
interface PasswordResetRequest {
  email: string;
}
```
**Response:** `{ message: "Password reset link sent to email" }`

### 2. Confirm Reset (`POST /auth/password-reset/confirm`)
**Request Body:**
```typescript
interface PasswordResetConfirm {
  token: string;
  newPassword: string; // Same validation as signup
}
```
**Response:** `{ message: "Password reset successful" }`

## Error Responses
All endpoints return standard HTTP status codes with error details:

```typescript
interface ErrorResponse {
  detail: string;
}

// Common error statuses:
// 400 - Bad Request (validation errors)
// 401 - Unauthorized (invalid credentials/token)
// 403 - Forbidden (account suspended/deactivated)
// 404 - Not Found
// 422 - Unprocessable Entity (validation errors)
```

## Frontend Implementation Examples

### React Hook for Authentication
```typescript
import { useState, useEffect, createContext, useContext } from 'react';

interface AuthContextType {
  user: UserResponse | null;
  token: string | null;
  login: (credentials: LoginRequest) => Promise<void>;
  signup: (data: SignupRequest) => Promise<void>;
  logout: () => void;
  refreshToken: () => Promise<void>;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Load token from localStorage on mount
    const storedToken = localStorage.getItem('access_token');
    if (storedToken) {
      setToken(storedToken);
      getCurrentUser(storedToken);
    } else {
      setIsLoading(false);
    }
  }, []);

  const login = async (credentials: LoginRequest) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail);
    }

    const data: TokenResponse = await response.json();
    setToken(data.access_token);
    setUser(data.user);
    localStorage.setItem('access_token', data.access_token);
    if (data.refresh_token) {
      localStorage.setItem('refresh_token', data.refresh_token);
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  };

  const getCurrentUser = async (accessToken: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });

      if (response.ok) {
        const userData: UserResponse = await response.json();
        setUser(userData);
      } else {
        logout();
      }
    } catch (error) {
      logout();
    } finally {
      setIsLoading(false);
    }
  };

  // ... implement signup, refreshToken functions

  return (
    <AuthContext.Provider value={{
      user, token, login, signup, logout, refreshToken, isLoading
    }}>
      {children}
    </AuthContext.Provider>
  );
}
```

### Protected Route Component
```typescript
import { useAuth } from './AuthProvider';
import { Navigate } from 'react-router-dom';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredUserType?: 'CREATOR' | 'COMPANY' | 'ADMIN';
  requiredPermission?: string;
}

export function ProtectedRoute({ 
  children, 
  requiredUserType,
  requiredPermission 
}: ProtectedRouteProps) {
  const { user, isLoading } = useAuth();

  if (isLoading) return <div>Loading...</div>;
  
  if (!user) return <Navigate to="/login" />;
  
  if (user.status !== 'ACTIVE') {
    return <Navigate to="/account-status" />;
  }

  if (requiredUserType && user.userType !== requiredUserType) {
    return <Navigate to="/unauthorized" />;
  }

  return <>{children}</>;
}
```

### Login Form Example
```typescript
import { useState } from 'react';
import { useAuth } from './AuthProvider';

export function LoginForm() {
  const [credentials, setCredentials] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await login(credentials);
      // Redirect handled by auth context
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Login failed');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && <div className="error">{error}</div>}
      
      <input
        type="email"
        placeholder="Email"
        value={credentials.email}
        onChange={(e) => setCredentials({...credentials, email: e.target.value})}
        required
      />
      
      <input
        type="password"
        placeholder="Password"
        value={credentials.password}
        onChange={(e) => setCredentials({...credentials, password: e.target.value})}
        required
      />
      
      <button type="submit">Login</button>
    </form>
  );
}
```

## Token Storage Recommendations

1. **Access Token:** Store in memory/state (expires in 1 hour)
2. **Refresh Token:** Store in httpOnly cookie or secure localStorage (expires in 7 days)
3. **Auto-refresh:** Implement token refresh 5-10 minutes before expiry

## Security Considerations

1. Always use HTTPS in production
2. Validate all user inputs on frontend before sending
3. Handle token expiry gracefully
4. Clear tokens on logout
5. Implement proper error handling for network failures
6. Consider implementing rate limiting on login attempts

## Account Status Handling

Users can have different statuses that affect UI behavior:
- **ACTIVE:** Full access
- **PENDING_VERIFICATION:** Show email verification prompt
- **SUSPENDED:** Show suspended account message
- **DEACTIVATED:** Redirect to reactivation flow

## User Type-Specific UI Elements

Based on `user.userType` and `user.profile`, show different UI:

- **Creator:** Show follower metrics, engagement stats, social accounts
- **Company:** Show company info, campaigns, brand management
- **Admin:** Show admin panel, user management, system controls

This reference provides everything needed to implement a complete authentication system for your frontend application.