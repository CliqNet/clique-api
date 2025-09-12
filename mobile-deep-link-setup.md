# Mobile Deep Link OAuth Setup Guide

This guide shows how to implement deep link-based OAuth for your Expo/React Native mobile app to handle Facebook (and other social media) connections.

## 1. Configure Your Expo App

### Update app.json/app.config.js

```json
{
  "expo": {
    "name": "Your App Name",
    "slug": "your-app-slug",
    "scheme": "myapp",
    "version": "1.0.0",
    "platforms": ["ios", "android"],
    "orientation": "portrait",
    "splash": {
      "image": "./assets/splash.png"
    },
    "updates": {
      "fallbackToCacheTimeout": 0
    },
    "assetBundlePatterns": [
      "**/*"
    ],
    "ios": {
      "supportsTablet": true,
      "bundleIdentifier": "com.yourcompany.yourapp"
    },
    "android": {
      "adaptiveIcon": {
        "foregroundImage": "./assets/adaptive-icon.png",
        "backgroundColor": "#FFFFFF"
      },
      "package": "com.yourcompany.yourapp",
      "intentFilters": [
        {
          "action": "VIEW",
          "autoVerify": true,
          "data": [
            {
              "scheme": "myapp"
            }
          ],
          "category": [
            "BROWSABLE",
            "DEFAULT"
          ]
        }
      ]
    }
  }
}
```

## 2. Install Required Dependencies

```bash
npx expo install expo-linking expo-constants @react-navigation/native
```

## 3. Implement Deep Link Handler

### Create a hook for deep link handling:

```javascript
// hooks/useDeepLink.js
import { useEffect, useState } from 'react';
import { Linking } from 'react-native';

export const useDeepLink = () => {
  const [url, setUrl] = useState(null);

  useEffect(() => {
    // Get the initial URL when app opens from background
    const getInitialUrl = async () => {
      const initialUrl = await Linking.getInitialURL();
      if (initialUrl) {
        setUrl(initialUrl);
      }
    };

    getInitialUrl();

    // Listen for URL changes when app is already open
    const subscription = Linking.addEventListener('url', ({ url }) => {
      setUrl(url);
    });

    return () => subscription?.remove();
  }, []);

  return url;
};
```

### Create OAuth service:

```javascript
// services/authService.js
import { Linking } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

const API_BASE_URL = 'https://08a51975b9d6.ngrok-free.app'; // Your ngrok URL

export const authService = {
  async connectSocialAccount(platform) {
    try {
      // Get JWT token from storage
      const token = await AsyncStorage.getItem('authToken');
      if (!token) {
        throw new Error('Please login first');
      }

      // Request OAuth URL from your backend
      const response = await fetch(`${API_BASE_URL}/api/v1/social/connect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          platform: platform.toLowerCase(),
          redirect_uri: 'myapp://auth/callback' // Deep link URI
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Connection failed');
      }

      const data = await response.json();
      
      // Open OAuth URL in browser
      const canOpen = await Linking.canOpenURL(data.oauth_url);
      if (canOpen) {
        await Linking.openURL(data.oauth_url);
      } else {
        throw new Error('Cannot open OAuth URL');
      }

      return data;
    } catch (error) {
      console.error('Social connect error:', error);
      throw error;
    }
  },

  async getConnectedAccounts() {
    try {
      const token = await AsyncStorage.getItem('authToken');
      if (!token) {
        throw new Error('Please login first');
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/social/accounts`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to fetch accounts');
      }

      const data = await response.json();
      return data.accounts;
    } catch (error) {
      console.error('Get accounts error:', error);
      throw error;
    }
  }
};
```

## 4. Create Social Connection Component

```javascript
// components/SocialConnections.js
import React, { useState, useEffect } from 'react';
import { 
  View, 
  Text, 
  TouchableOpacity, 
  Alert, 
  ActivityIndicator,
  StyleSheet 
} from 'react-native';
import { useDeepLink } from '../hooks/useDeepLink';
import { authService } from '../services/authService';

const SUPPORTED_PLATFORMS = [
  { name: 'Facebook', key: 'facebook', color: '#1877F2' },
  { name: 'Instagram', key: 'instagram', color: '#E4405F' },
  { name: 'Twitter', key: 'twitter', color: '#1DA1F2' },
  { name: 'YouTube', key: 'youtube', color: '#FF0000' },
  { name: 'TikTok', key: 'tiktok', color: '#000000' },
  { name: 'LinkedIn', key: 'linkedin', color: '#0A66C2' }
];

export const SocialConnections = () => {
  const [connectedAccounts, setConnectedAccounts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [connecting, setConnecting] = useState(null);
  const deepLinkUrl = useDeepLink();

  // Load connected accounts on mount
  useEffect(() => {
    loadConnectedAccounts();
  }, []);

  // Handle deep link responses
  useEffect(() => {
    if (deepLinkUrl && deepLinkUrl.includes('auth/callback')) {
      handleOAuthCallback(deepLinkUrl);
    }
  }, [deepLinkUrl]);

  const loadConnectedAccounts = async () => {
    try {
      setLoading(true);
      const accounts = await authService.getConnectedAccounts();
      setConnectedAccounts(accounts);
    } catch (error) {
      Alert.alert('Error', 'Failed to load connected accounts');
    } finally {
      setLoading(false);
    }
  };

  const handleOAuthCallback = (url) => {
    const urlParams = new URLSearchParams(url.split('?')[1]);
    const success = urlParams.get('success');
    const platform = urlParams.get('platform');
    const error = urlParams.get('error');
    const accountId = urlParams.get('account_id');

    setConnecting(null); // Clear connecting state

    if (success === 'true') {
      Alert.alert(
        'Success!', 
        `${platform} account connected successfully!`,
        [{ text: 'OK', onPress: () => loadConnectedAccounts() }]
      );
    } else if (error) {
      Alert.alert('Connection Failed', decodeURIComponent(error));
    }
  };

  const connectPlatform = async (platform) => {
    try {
      setConnecting(platform.key);
      await authService.connectSocialAccount(platform.key);
      // OAuth flow will continue in browser, callback will be handled by deep link
    } catch (error) {
      setConnecting(null);
      Alert.alert('Error', error.message);
    }
  };

  const isConnected = (platformKey) => {
    return connectedAccounts.some(account => 
      account.platform.toLowerCase() === platformKey.toLowerCase()
    );
  };

  if (loading) {
    return (
      <View style={styles.container}>
        <ActivityIndicator size="large" />
        <Text>Loading accounts...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Connect Your Social Accounts</Text>
      
      {SUPPORTED_PLATFORMS.map((platform) => {
        const connected = isConnected(platform.key);
        const isConnecting = connecting === platform.key;
        
        return (
          <TouchableOpacity
            key={platform.key}
            style={[
              styles.platformButton,
              { backgroundColor: connected ? '#4CAF50' : platform.color },
              isConnecting && styles.connectingButton
            ]}
            onPress={() => !connected && !isConnecting && connectPlatform(platform)}
            disabled={connected || isConnecting}
          >
            {isConnecting ? (
              <View style={styles.connectingContent}>
                <ActivityIndicator color="white" size="small" />
                <Text style={styles.buttonText}>Connecting...</Text>
              </View>
            ) : (
              <Text style={styles.buttonText}>
                {connected ? `✓ ${platform.name} Connected` : `Connect ${platform.name}`}
              </Text>
            )}
          </TouchableOpacity>
        );
      })}

      <Text style={styles.connectedCount}>
        Connected: {connectedAccounts.length} account(s)
      </Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#f5f5f5',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
  },
  platformButton: {
    padding: 15,
    marginVertical: 8,
    borderRadius: 8,
    alignItems: 'center',
  },
  connectingButton: {
    opacity: 0.7,
  },
  connectingContent: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
  connectedCount: {
    marginTop: 20,
    textAlign: 'center',
    fontSize: 16,
    color: '#666',
  },
});
```

## 5. Integrate in Your Main App

```javascript
// App.js
import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { SocialConnections } from './components/SocialConnections';

const Stack = createStackNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator>
        {/* Your other screens */}
        <Stack.Screen 
          name="SocialConnections" 
          component={SocialConnections}
          options={{ title: 'Social Accounts' }}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
```

## 6. Test the Implementation

### Testing Steps:
1. **Build and install your app**: `npx expo run:android` or `npx expo run:ios`
2. **Make sure your backend is running**: `uvicorn app.main:app --reload`
3. **Ensure ngrok is active**: Update `API_BASE_URL` with your current ngrok URL
4. **Test the flow**:
   - Open your app
   - Navigate to Social Connections
   - Tap "Connect Facebook"
   - App opens Facebook OAuth in browser
   - Complete Facebook authorization
   - Browser redirects to `myapp://auth/callback`
   - Your app should open and show success message

### Debugging Tips:

1. **Test deep links manually**:
   ```bash
   # Android
   adb shell am start -W -a android.intent.action.VIEW -d "myapp://auth/callback?success=true&platform=FACEBOOK" com.yourcompany.yourapp
   
   # iOS Simulator
   xcrun simctl openurl booted "myapp://auth/callback?success=true&platform=FACEBOOK"
   ```

2. **Check logs**:
   ```bash
   npx expo logs
   ```

3. **Verify URL scheme**:
   - Make sure the scheme in your app.json matches what you use in the redirect_uri
   - The scheme should be unique to your app

## 7. Production Considerations

1. **Use environment variables** for API URLs
2. **Add error handling** for network failures
3. **Implement token refresh** logic
4. **Add loading states** for better UX
5. **Test on both iOS and Android**
6. **Consider adding universal links** for iOS

This setup will handle the OAuth flow entirely within your mobile app using deep links, eliminating the browser redirect issue you were experiencing.