# Facebook Account Connection Guide

This guide walks you through connecting your Facebook account to the Clique platform to sync your profile data, followers, and engagement metrics.

## Overview

The Facebook integration allows you to:
- Import your Facebook profile information (name, bio, location, website)
- Sync follower counts and engagement metrics
- Track page insights for Facebook pages
- Monitor account health and token status
- Auto-refresh data every 6 hours

## Prerequisites

Before connecting your Facebook account:
1. You must be logged into your Clique account
2. Your Facebook account should have appropriate permissions
3. For pages: You need admin access to the Facebook page you want to connect

## Connection Process

### Step 1: Initiate Connection

**API Endpoint:** `POST /api/v1/social/connect`

```json
{
  "platform": "facebook",
  "redirect_uri": "https://yourapp.com/callback"
}
```

**UI Flow:**
1. Navigate to your Creator Dashboard → Social Accounts
2. Click "Connect Facebook Account"
3. The system will redirect you to Facebook's OAuth authorization page

### Step 2: Facebook Authorization

You'll be redirected to Facebook where you need to:
1. Log into your Facebook account if not already logged in
2. Review the permissions requested:
   - `public_profile`: Basic profile information
   - `pages_read_engagement`: Read engagement metrics for pages you manage
   - `read_insights`: Access to page insights data
3. Click "Continue" to authorize the connection

### Step 3: Callback Processing

After authorization, Facebook redirects back to:
- **Success**: `https://yourapp.com/creator/accounts?success=true&platform=FACEBOOK`
- **Error**: `https://yourapp.com/creator/accounts?error=<error_message>`

The system automatically:
1. Validates the OAuth state parameter for security
2. Retrieves the exact redirect_uri used in step 1 to ensure consistency
3. Exchanges the authorization code for access tokens using the same redirect_uri
4. Stores tokens securely in the database
5. Initiates first data sync in the background
6. Sends real-time notifications via WebSocket

**Important**: The redirect_uri must match exactly between the authorization request and token exchange, or Facebook will reject the request with an "invalid_grant" error.

## Data Synchronization

### What Gets Synced

**Profile Data:**
- Display name
- Profile picture (200x200px)
- Bio/About section
- Website URL
- Location
- Follower count

**Page Insights (if connecting a page):**
- Page fans (followers)
- Engaged users (7-day average)
- Post engagements
- Engagement rate calculation

### Sync Schedule

- **Initial sync**: Within 5 seconds of connection
- **Regular sync**: Every 6 hours automatically
- **Manual sync**: Available via API or dashboard
- **Error retry**: Every 1 hour if sync fails

## API Endpoints

### Get Connected Accounts
```http
GET /api/v1/social/accounts
Authorization: Bearer <your_jwt_token>
```

**Response:**
```json
{
  "accounts": [
    {
      "id": "account_id",
      "platform": "FACEBOOK",
      "username": "your_username",
      "displayName": "Your Display Name",
      "avatar": "https://...",
      "followers": 1250,
      "avgEngagement": 3.5,
      "status": "CONNECTED",
      "syncStatus": "COMPLETED",
      "last_sync": "2025-01-10T10:30:00Z",
      "expires_at": "2025-03-10T10:30:00Z"
    }
  ]
}
```

### Manual Sync
```http
POST /api/v1/social/sync
Authorization: Bearer <your_jwt_token>
Content-Type: application/json

{
  "account_id": "your_account_id"
}
```

### Check Sync Status
```http
GET /api/v1/social/sync/status/{account_id}
Authorization: Bearer <your_jwt_token>
```

### Disconnect Account
```http
POST /api/v1/social/disconnect
Authorization: Bearer <your_jwt_token>
Content-Type: application/json

{
  "account_id": "your_account_id"
}
```

## Token Management

### Automatic Token Refresh
- Facebook tokens expire every 60 days by default
- The system automatically refreshes tokens when they're close to expiration
- Long-lived tokens are requested during initial connection

### Token Status Monitoring
- Check token expiration: `GET /api/v1/social/health/{account_id}`
- Manual refresh: `POST /api/v1/social/refresh/{account_id}`
- Admin bulk refresh: `POST /api/v1/social/admin/refresh-expired-tokens`

## Error Handling

### Common Connection Errors

**"invalid_grant"**
- Cause: User denied permission or authorization code expired
- Solution: Retry the connection process

**"insufficient_permissions"**
- Cause: Required permissions not granted
- Solution: Reconnect and ensure all permissions are accepted

**"token_expired"**
- Cause: Access token has expired
- Solution: Use refresh token or reconnect account

**"rate_limit_exceeded"**
- Cause: Too many API requests to Facebook
- Solution: Wait for rate limit reset (usually 1 hour)

### Sync Status Values

- `PENDING`: Sync not yet started
- `SYNCING`: Currently fetching data
- `COMPLETED`: Successfully synced
- `FAILED`: Sync encountered an error
- `RATE_LIMITED`: Temporarily blocked due to rate limits

## Troubleshooting

### Connection Issues

**Problem: Can't connect Facebook account**
1. Ensure you're logged into Facebook
2. Check that your Facebook account has the required permissions
3. Try clearing browser cache and cookies
4. Verify the redirect URI is correct

**Problem: Data not syncing**
1. Check sync status: `GET /api/v1/social/sync/status/{account_id}`
2. Verify token hasn't expired
3. Check for rate limiting
4. Try manual sync

### Rate Limits

Facebook has the following rate limits:
- **User access tokens**: 200 calls per hour per user
- **Page access tokens**: 4800 calls per hour per page
- **App access tokens**: 200 calls per hour per app

If you hit rate limits:
- Wait for the reset period (shown in error response)
- Reduce sync frequency if needed
- Contact support for high-volume needs

## Security & Privacy

### Data Protection
- All tokens are encrypted at rest
- Only necessary permissions are requested
- Data is synced securely over HTTPS
- Tokens are automatically rotated

### Permission Scopes
The integration requests minimal permissions:
- `public_profile`: For basic profile information
- `pages_read_engagement`: For page metrics (pages only)
- `read_insights`: For detailed engagement data

### Data Retention
- Profile data is updated on each sync
- Historical metrics may be stored for analytics
- Account data is removed when disconnected
- Tokens are securely deleted on disconnection

## Support

### Real-time Updates
- WebSocket notifications for connection status
- Real-time sync progress updates
- Token expiration alerts

### Monitoring
- Account health checks
- Sync status monitoring
- Rate limit tracking
- Error logging and alerts

For technical support or integration issues, contact the development team or check the API logs for detailed error information.