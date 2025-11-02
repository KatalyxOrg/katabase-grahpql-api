# Refresh Token Implementation

This document describes the refresh token mechanism implemented in the Katabase GraphQL API.

## Overview

The refresh token mechanism provides a secure way to maintain user sessions without requiring frequent re-authentication. It follows industry best practices including:

- **Short-lived access tokens** (30 minutes)
- **Long-lived refresh tokens** (30 days)
- **Automatic token rotation** on refresh
- **Reuse detection** for security breach prevention
- **Secure storage** with bcrypt hashing

## Architecture

### Components

1. **Database Model** (`pkg/database/dbmodel/refreshtoken.go`)

   - `RefreshToken` model with GORM
   - Repository interface with methods for CRUD operations
   - Support for token families (rotation tracking)

2. **Service Layer** (`internal/authentication/refresh.go`)

   - `GenerateRefreshToken()` - Creates new refresh token
   - `RotateRefreshToken()` - Rotates token during refresh
   - `ValidateRefreshToken()` - Validates token
   - `RevokeRefreshToken()` - Revokes specific token
   - Secure hashing with bcrypt

3. **JWT Updates** (`internal/authentication/jwt.go`)

   - Updated `GenerateToken()` to accept TTL parameter
   - Added JTI (JWT ID) claim for token tracking
   - Configurable token expiration

4. **GraphQL API**

   - Updated `LoginResult` type to include `refreshToken`
   - New `refreshToken` mutation for token refresh
   - Both mutations return new access and refresh tokens

5. **Configuration** (`config/config.go`, `config.yml`)
   - `jwt.accessTokenTTL` - Access token lifetime (default: 30m)
   - `jwt.refreshTokenTTL` - Refresh token lifetime (default: 720h / 30 days)

## Database Schema

```sql
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP,

    user_id INTEGER NOT NULL REFERENCES users(id),
    token_hash VARCHAR NOT NULL UNIQUE,
    family_id VARCHAR NOT NULL,

    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    last_used_at TIMESTAMP,

    user_agent VARCHAR,
    ip_address VARCHAR
);

CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
```

## API Usage

### 1. Login

```graphql
mutation Login {
  login(input: { email: "user@example.com", password: "password" }) {
    user {
      id
      email
    }
    token # Access token (30 min)
    refreshToken # Refresh token (30 days)
    permissions
    roles
  }
}
```

**Response:**

```json
{
  "data": {
    "login": {
      "user": { "id": "1", "email": "user@example.com" },
      "token": "eyJhbGciOiJIUzI1NiIs...",
      "refreshToken": "d3h5eXc5eDk5eHg5OXh4...",
      "permissions": ["read:user:self"],
      "roles": ["user"]
    }
  }
}
```

### 2. Refresh Access Token

When the access token expires (after 30 minutes), use the refresh token:

```graphql
mutation RefreshToken {
  refreshToken(refreshToken: "d3h5eXc5eDk5eHg5OXh4...") {
    user {
      id
      email
    }
    token # New access token
    refreshToken # New refresh token (old one revoked)
    permissions
    roles
  }
}
```

### 3. Using Access Token

Include the access token in the `Authorization` header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

## Security Features

### 1. Token Rotation

Every time a refresh token is used:

1. The old refresh token is **immediately revoked**
2. A **new refresh token** is generated in the same family
3. A **new access token** is generated

This ensures that each refresh token can only be used once.

### 2. Reuse Detection

If an already-used (revoked) refresh token is presented:

1. The system detects the reuse attempt
2. **All tokens in that family are revoked** immediately
3. An error is returned: `"refresh token reuse detected - all tokens in family revoked"`

This protects against token theft - if a stolen token is used after the legitimate user has already refreshed it, all tokens are invalidated and both parties must re-authenticate.

### 3. Secure Storage

- Refresh tokens are **hashed with bcrypt** before storage
- Only the hash is stored in the database
- Original tokens are never logged or stored in plain text
- Database contains: user_id, token_hash, family_id, expiration, metadata

### 4. Token Families

Each refresh token belongs to a **family** (identified by `family_id`):

- When a user logs in, a new family is created
- Each rotation creates a new token in the same family
- If reuse is detected, the entire family is revoked
- Families are independent per login session

### 5. Metadata Tracking

Each refresh token stores:

- `user_agent` - Browser/client information
- `ip_address` - Source IP address
- `last_used_at` - Last refresh timestamp
- `expires_at` - Token expiration time

This enables:

- Session management (view active sessions)
- Anomaly detection (new device/location)
- Security auditing

## Error Handling

The system provides clear error messages:

| Error                          | Description                  | Action                      |
| ------------------------------ | ---------------------------- | --------------------------- |
| `invalid refresh token`        | Token not found or malformed | Re-authenticate             |
| `refresh token expired`        | Token older than 30 days     | Re-authenticate             |
| `refresh token revoked`        | Token was manually revoked   | Re-authenticate             |
| `refresh token reuse detected` | Security breach detected     | Re-authenticate immediately |

## Configuration

### Default Values

```yaml
jwt:
  accessTokenTTL: 30m # Access token expires in 30 minutes
  refreshTokenTTL: 720h # Refresh token expires in 30 days (720 hours)
```

### Customization

You can adjust these values in `config.yml`:

```yaml
jwt:
  accessTokenTTL: 15m # Shorter for high-security applications
  refreshTokenTTL: 168h # 7 days for mobile apps
```

Time units supported: `h` (hours), `m` (minutes), `s` (seconds)

## Best Practices

### Client-Side Implementation

1. **Store both tokens securely**

   - Access token: Memory or secure storage
   - Refresh token: Secure storage only (HTTP-only cookie or encrypted storage)

2. **Automatic token refresh**

   ```javascript
   // Pseudo-code
   async function apiCall(query) {
     try {
       return await graphql(query, { token: accessToken });
     } catch (error) {
       if (error.code === "UNAUTHENTICATED") {
         // Access token expired, refresh it
         const result = await refreshToken(refreshToken);
         accessToken = result.token;
         refreshToken = result.refreshToken;

         // Retry original request
         return await graphql(query, { token: accessToken });
       }
       throw error;
     }
   }
   ```

3. **Handle refresh failures**
   - If refresh fails, redirect to login
   - Clear all stored tokens
   - Show appropriate error message

### Server-Side

1. **Monitor for suspicious activity**

   - Multiple refresh failures
   - Refresh from new locations/devices
   - Token reuse detection events

2. **Implement session limits**

   - Limit concurrent sessions per user
   - Force logout on password change
   - Provide "logout all devices" functionality

3. **Regular cleanup**
   - Delete expired tokens regularly
   - Archive/purge old audit logs
   - Monitor token family sizes

## Future Enhancements

Potential improvements for the future:

1. **Session Management UI**

   - List active sessions
   - Revoke individual sessions
   - Show device/location information

2. **Advanced Security**

   - Fingerprint validation (device consistency)
   - IP address change detection
   - Geographic anomaly detection

3. **Notifications**

   - Email on new device login
   - Alert on token reuse detection
   - Session activity summaries

4. **Token Blacklist**
   - For revoked access tokens
   - Prevent use until expiration
   - Cache in Redis for performance

## Testing

Use the Bruno collection files in `bruno/Katabase GraphQL/Authentication/`:

1. **Login.bru** - Get initial tokens
2. **Refresh Token.bru** - Test token refresh
3. Verify rotation by attempting to reuse old refresh token

## Migration Guide

For existing deployments:

1. **Run database migration** - `RefreshToken` table will be created automatically
2. **Update config.yml** - Add JWT configuration (or use defaults)
3. **Update clients** - Store and use the new `refreshToken` field
4. **Deploy** - Old access tokens will continue to work until they expire

## Summary

The refresh token mechanism provides:

✅ **Security** - Short-lived access tokens, rotation, reuse detection  
✅ **User Experience** - No frequent re-authentication required  
✅ **Flexibility** - Configurable TTLs, multiple sessions  
✅ **Auditability** - Full tracking of token usage and metadata  
✅ **Standards Compliance** - Follows OAuth 2.0 best practices

This implementation balances security and usability while maintaining compatibility with the existing Katabase GraphQL architecture.
