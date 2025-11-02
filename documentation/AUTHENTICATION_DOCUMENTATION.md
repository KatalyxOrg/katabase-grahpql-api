# Authentication Mechanism Documentation

This document describes the authentication system implemented in the Katabase GraphQL API.

## Overview

The Katabase GraphQL API uses a **dual-token JWT authentication system** combining short-lived access tokens with long-lived refresh tokens. This approach balances security (minimal exposure of credentials) with user experience (persistent sessions without frequent re-authentication).

### Key Features

- **Email + Password authentication** with bcrypt hashing (cost factor: 14)
- **JWT-based access tokens** (30-minute default TTL)
- **Refresh token rotation** (30-day default TTL)
- **Role-Based Access Control (RBAC)** via GraphQL directives and service-layer checks
- **WebSocket authentication** for real-time subscriptions
- **User agent and IP tracking** for security auditing
- **Future OAuth support** (Google/Microsoft/Apple) for SSO and calendar sync

---

## Architecture

### Components

1. **Service Layer** (`internal/authentication/service.go`)

   - `Login()` - Email/password authentication
   - `CreateUser()` - User registration with password hashing
   - `UpdateUser()` - Profile updates with permission checks
   - `RefreshAccessToken()` - Token refresh with rotation
   - `GetAllPermissions()` - Permission enumeration for admin tools

2. **JWT Management** (`internal/authentication/jwt.go`)

   - `GenerateToken()` - Creates signed JWT with configurable TTL and JTI claim
   - `ParseToken()` - Validates and extracts user ID from token

3. **Refresh Token System** (`internal/authentication/refresh.go`)

   - `GenerateRefreshToken()` - Creates SHA256-hashed token with family tracking
   - `RotateRefreshToken()` - Implements token rotation on refresh
   - `ValidateRefreshToken()` - Validates token and checks revocation/expiration
   - `RevokeRefreshToken()` - Revokes specific token
   - `RevokeAllUserRefreshTokens()` - Logout from all devices

4. **Middleware** (`internal/authentication/middleware.go`)

   - `Middleware()` - HTTP middleware for extracting user from JWT
   - `WebsocketInitFunc()` - WebSocket connection authentication
   - `ForContext()` - Context helper to retrieve authenticated user

5. **GraphQL API** (`graph/schema/root.graphqls`)

   - `login` mutation - Returns `LoginResult` with tokens and permissions
   - `refreshToken` mutation - Rotates tokens and returns new credentials
   - `@hasPermission` directive - Declarative authorization on fields
   - `me` query - Returns current user profile

6. **Database Models** (`pkg/database/dbmodel/`)
   - `User` - Core user entity with password hash
   - `Role` - Role definitions with permission associations
   - `Permission` - Granular permissions (e.g., `read:user:self`)
   - `PermissionOverride` - User-specific grants/denials
   - `RefreshToken` - Refresh token storage with metadata

---

## Authentication Flow

### 1. User Registration

```graphql
mutation CreateUser {
  createUser(input: { email: "tenant@example.com", password: "SecurePass123!", userProfile: { firstName: "Marie", lastName: "Dupont" } }) {
    id
    email
    userProfile {
      firstName
      lastName
    }
  }
}
```

**Process:**

1. Email uniqueness check via `UserRepository.FindByEmail`
2. Password hashing with bcrypt (cost: 14) via `HashPassword()`
3. Default role assignment (`user` role from seed)
4. User creation via `UserRepository.Create`

**Security:**

- Passwords never stored in plain text
- Email uniqueness enforced at DB level
- Default role prevents privilege escalation

---

### 2. Login (Initial Authentication)

```graphql
mutation Login {
  login(input: { email: "tenant@example.com", password: "SecurePass123!" }) {
    user {
      id
      email
      permissions
      roles
    }
    token # Access token (30 min)
    refreshToken # Refresh token (30 days)
    permissions # Flattened permission list
    roles # Role names
  }
}
```

**Process:**

1. User lookup by email with eager-loaded roles and permissions
2. Password verification via `CheckPasswordHash()`
3. Access token generation via `GenerateToken()`
   - Claims: `id` (user ID), `jti` (unique token ID), `exp`, `iat`
   - Signed with HS256 using `jwt.secret` from config
4. Refresh token generation via `GenerateRefreshToken()`
   - 32-byte cryptographically random token (base64-encoded)
   - SHA256 hash stored in database
   - Assigned to new token family (UUID)
   - User agent and IP address captured for auditing
5. Permission list compiled from all assigned roles

**Response Structure:**

```json
{
  "data": {
    "login": {
      "user": { "id": "42", "email": "tenant@example.com" },
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "rhr8tgikaTB7Piy4CKHmxmwSDR-7ByQrt2gUBmSdxkY=",
      "permissions": ["read:user:self", "listing:read:any"],
      "roles": ["user"]
    }
  }
}
```

---

### 3. Authenticated Requests

**HTTP Requests:**

Include access token in `Authorization` header:

```http
POST /query HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "query": "query { me { id email } }"
}
```

**Process:**

1. `Middleware()` extracts token from header
2. Token validated and user ID extracted via `ParseToken()`
3. User loaded from database with roles and permissions
4. User injected into request context via `context.WithValue()`
5. Resolver can access user via `authentication.ForContext(ctx)`

**WebSocket Connections:**

Authentication occurs during connection initialization:

```javascript
// Client-side (JavaScript example)
const wsClient = createClient({
  url: "wss://api.katabasegql.fr/query",
  connectionParams: {
    Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  },
});
```

**Process:**

1. `WebsocketInitFunc()` extracts token from connection params
2. Token validated and user loaded (same as HTTP)
3. User injected into WebSocket context
4. Subscriptions can check permissions via context

---

### 4. Token Refresh

When access token expires (30 minutes):

```graphql
mutation RefreshToken {
  refreshToken(refreshToken: "rhr8tgikaTB7Piy4CKHmxmwSDR-7ByQrt2gUBmSdxkY=") {
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

**Process:**

1. Refresh token hashed via SHA256 for database lookup
2. Token validation via `ValidateRefreshToken()`
   - Check existence in database
   - Check revocation status
   - Check expiration (30 days default)
   - **Reuse detection**: If token already revoked, revoke entire family
3. Token rotation via `RotateRefreshToken()`
   - Revoke old token (set `revoked_at`)
   - Generate new token in same family
   - Update `last_used_at` timestamp
4. New access token generated via `GenerateToken()`
5. Return new credentials

**Security Features:**

- **Automatic rotation**: Each refresh token is single-use
- **Reuse detection**: Stolen tokens trigger family-wide revocation
- **Family tracking**: All tokens from same login session linked
- **Metadata**: IP and user agent changes logged for anomaly detection

---

## Authorization (RBAC)

### GraphQL Directive

Fields annotated with `@hasPermission` require authentication and specific permissions:

```graphql
type Query {
  me: User! @hasPermission(permissions: ["read:user:self"])
  users: [User!]! @hasPermission(permissions: ["read:user"])
}

type Mutation {
  updateUser(id: ID!, input: UpdateUserInput!): User! @hasPermission(permissions: ["update:user", "update:user:self"])
}
```

**Implementation** (`server.go`):

```go
c.Directives.HasPermission = func(ctx context.Context, obj interface{}, next graphql.Resolver, permissions []string) (res interface{}, err error) {
    user := authentication.ForContext(ctx)

    if user == nil {
        return nil, &errormsg.UserAccessDeniedError{}
    }

    // Build permission set from required permissions
    permissionSet := make(map[string]struct{}, len(permissions))
    for _, permission := range permissions {
        permissionSet[permission] = struct{}{}
    }

    // Check user's roles for any matching permission
    for _, role := range user.Roles {
        for _, rolePermission := range roles.Permissions {
            if _, exists := permissionSet[rolePermission.Name]; exists {
                return next(ctx) // Permission granted
            }
        }
    }

    return nil, &errormsg.UserAccessDeniedError{}
}
```

**Evaluation Logic:**

1. Extract user from context
2. If no user → `UNAUTHENTICATED`
3. Build set of required permissions (OR semantics)
4. Check user's roles for any matching permission
5. If match found → execute resolver
6. If no match → `FORBIDDEN`

### Permission Model

**Current Permissions** (from seed in `pkg/database/seed/seedv1.go`):

- **User Role:**

  - `read:user:self` - Read own profile

- **Admin Role:**
  - `read:user` - Read any user
  - `create:user` - Create users
  - `update:user` - Update any user
  - `delete:user` - Delete users
  - `read:permission:all` - List all permissions
  - `update:permission:override` - Grant/deny user-specific permissions

**Permission Overrides:**

Admins can grant or deny specific permissions to individual users via `PermissionOverride`:

```graphql
mutation GrantPermission {
  updatePermissionOverride(
    input: {
      userId: 42
      permissionId: 7
      isGranted: true # Grant permission
    }
  )
}
```

**Future Scope-Based Permissions:**

Planned format: `resource:action[:scope]`

Examples:

- `listing:create` - Create listings (landlord)
- `application:read:self` - Read own applications (tenant)
- `scoring:read:self` - View own score (tenant)
- `admin:*` - Wildcard admin access

---

## Security Best Practices

### Password Security

1. **Hashing Algorithm:** bcrypt with cost factor 14
2. **Password Requirements:** Enforced client-side (minimum length, complexity)
3. **Storage:** Only hashes stored in `User.PasswordHash`
4. **Legacy Compatibility:** Fallback check for old `$2y$` hashes (PHP compatibility)

### Token Security

1. **Access Tokens:**

   - Short TTL (30 minutes) minimizes exposure window
   - Stateless validation (no DB lookup required)
   - JTI claim for optional blacklisting (future)

2. **Refresh Tokens:**

   - SHA256 hashed (deterministic for lookups)
   - Stored with metadata (IP, user agent) for auditing
   - Family-based rotation prevents replay attacks
   - Automatic revocation on reuse detection

3. **Transport:**
   - HTTPS/WSS only (enforced via reverse proxy)
   - Tokens never logged in plain text
   - CORS configured in server.go

### Session Management

**Current:**

- Multiple concurrent sessions supported (one refresh token per login)
- No automatic session limits

**Future Enhancements:**

- Session management UI (list/revoke active sessions)
- Device fingerprinting for anomaly detection
- Email notifications on new device login
- Force logout on password change
- Configurable session limits per user

---

## Error Handling

### Authentication Errors

| Error Code                       | GraphQL Extension | Trigger                | Action                                            |
| -------------------------------- | ----------------- | ---------------------- | ------------------------------------------------- |
| `UserNotFoundError`              | `UNAUTHENTICATED` | Invalid email on login | Verify credentials                                |
| `UserInvalidCredentialsError`    | `UNAUTHENTICATED` | Wrong password         | Verify credentials                                |
| `UserAccessDeniedError`          | `FORBIDDEN`       | Missing permission     | Check role assignments                            |
| `RefreshTokenInvalidError`       | `UNAUTHENTICATED` | Token not found        | Re-authenticate                                   |
| `RefreshTokenExpiredError`       | `UNAUTHENTICATED` | Token > 30 days old    | Re-authenticate                                   |
| `RefreshTokenRevokedError`       | `UNAUTHENTICATED` | Token manually revoked | Re-authenticate                                   |
| `RefreshTokenReuseDetectedError` | `UNAUTHENTICATED` | Token reuse attempt    | **Re-authenticate immediately** (security breach) |

**Example Error Response:**

```json
{
  "errors": [
    {
      "message": "invalid credentials",
      "extensions": {
        "code": "UNAUTHENTICATED"
      }
    }
  ]
}
```

### Client-Side Handling

```javascript
// Pseudo-code for automatic refresh
async function makeAuthenticatedRequest(query) {
  try {
    return await graphql(query, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  } catch (error) {
    if (error.extensions?.code === "UNAUTHENTICATED" && refreshToken) {
      // Attempt token refresh
      const result = await refreshTokenMutation(refreshToken);

      if (result.data) {
        // Update tokens
        accessToken = result.data.refreshToken.token;
        refreshToken = result.data.refreshToken.refreshToken;

        // Retry original request
        return await graphql(query, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
      }
    }

    // Refresh failed or other error → redirect to login
    redirectToLogin();
    throw error;
  }
}
```

---

## Configuration

### JWT Settings (`config.yml`)

```yaml
jwt:
  secret: "your-secret-key-here" # HS256 signing key (rotate regularly)
  accessTokenTTL: 30m # Access token lifetime
  refreshTokenTTL: 720h # Refresh token lifetime (30 days)
```

**Environment Overrides:**

All config values can be overridden via environment variables (see `config/config.go`):

```bash
JWT_SECRET=production-secret-key
JWT_ACCESSTOKENTTL=15m
JWT_REFRESHTOKENTTL=168h  # 7 days for mobile apps
```

**Time Units:**

- `h` - hours
- `m` - minutes
- `s` - seconds

**Security Recommendations:**

- Access token: 15-30 minutes (balance security vs. UX)
- Refresh token: 7-30 days (mobile apps may need longer)
- Rotate `jwt.secret` on suspected compromise
- Use strong secret (minimum 32 bytes, cryptographically random)

---

## Database Schema

### Users Table

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,  -- Soft delete

    email VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR,  -- bcrypt hash, nullable for OAuth-only users

    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

CREATE INDEX idx_users_email ON users(email);
```

### Roles & Permissions Tables

```sql
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    name VARCHAR UNIQUE NOT NULL
);

CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    name VARCHAR UNIQUE NOT NULL,
    readable_name VARCHAR NOT NULL,
    description TEXT,
    category VARCHAR
);

-- Many-to-many: Roles → Permissions
CREATE TABLE role_permissions (
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Many-to-many: Users → Roles
CREATE TABLE user_roles (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- User-specific overrides (grant/deny)
CREATE TABLE user_permission_overrides (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,

    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    is_granted BOOLEAN NOT NULL,

    UNIQUE (user_id, permission_id)
);
```

### Refresh Tokens Table

```sql
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,

    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR UNIQUE NOT NULL,  -- SHA256 hash
    family_id VARCHAR NOT NULL,          -- UUID for rotation tracking

    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    last_used_at TIMESTAMP,

    user_agent VARCHAR,
    ip_address VARCHAR
);

CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);  -- For cleanup
```

---

## Testing

### Bruno Test Collection

The Authentication folder contains ready-to-use tests:

1. **[Create User.bru](bruno/Katabase GraphQL/Authentication/Create User.bru)** - User registration
2. **Login.bru** - Initial authentication
3. **[Refresh Token.bru](bruno/Katabase GraphQL/Authentication/Refresh Token.bru)** - Token refresh

**Test Scenarios:**

✅ **Happy Path:**

1. Create user → verify default role assigned
2. Login → receive access + refresh tokens
3. Call `me` query with access token → success
4. Wait 31 minutes → access token expires
5. Refresh with refresh token → new tokens received
6. Call `me` with new access token → success

✅ **Security Tests:**

1. Reuse old refresh token → `refresh token reuse detected` error
2. Attempt refresh after family revocation → `invalid refresh token`
3. Call protected query without token → `UNAUTHENTICATED`
4. Call admin query with user role → `FORBIDDEN`

---

## Migration Guide

### For Existing Deployments

1. **Database Migration:**

   - GORM auto-migrates `refresh_tokens` table on startup (see `pkg/database/database.go`)
   - Run seed if roles/permissions don't exist (see `pkg/database/seed/seedv1.go`)

2. **Configuration:**

   - Add JWT config to config.yml (or use defaults)
   - Rotate `jwt.secret` if currently using default value

3. **Client Updates:**

   - Update login/register flows to store `refreshToken` field
   - Implement automatic refresh logic (see example above)
   - Handle `RefreshTokenReuseDetectedError` → force logout

4. **Deployment:**
   - Old access tokens remain valid until expiration
   - No breaking changes to existing endpoints

---

## Future Enhancements

### OAuth Integration (Planned)

**Providers:** Google, Microsoft, Apple

**Use Cases:**

1. **SSO:** Passwordless login via OAuth
2. **Calendar Sync:** Bidirectional sync for visit scheduling (see Architecture Guidelines)

**Implementation Plan:**

1. Add OAuth config to config.go (framework already present)
2. Create `OAuthProvider` table to link users with external accounts
3. Add `loginWithOAuth` mutation
4. Generate refresh token on successful OAuth callback
5. Store access/refresh tokens for provider API calls

### Enhanced Security

1. **Rate Limiting:**

   - Login attempts: 5 per 15 minutes per IP
   - Refresh token requests: 10 per hour per user
   - WebSocket connections: 5 concurrent per user

2. **Device Fingerprinting:**

   - Browser fingerprint hashing
   - Anomaly detection (new device → email notification)
   - Optional MFA for new devices

3. **Access Token Blacklist:**

   - Redis-based revocation list
   - Force logout invalidates all access tokens
   - Cache until expiration (30 min max)

4. **Audit Logging:**
   - Structured logs with `trace_id`, subject, action, status
   - Log all ALLOW/DENY authorization decisions
   - Retention policy (90 days, then archive)

### Session Management UI

**Endpoint:** `query activeSessions { ... }`

**Fields:**

- Device info (user agent, IP, location)
- Last activity timestamp
- Refresh token family ID
- Revoke action

**GraphQL Schema:**

```graphql
type Session {
  id: ID!
  createdAt: DateTime!
  lastUsedAt: DateTime!
  expiresAt: DateTime!
  userAgent: String
  ipAddress: String
  isCurrent: Boolean!
}

type Query {
  activeSessions: [Session!]! @hasPermission(permissions: ["read:session:self"])
}

type Mutation {
  revokeSession(id: ID!): Boolean! @hasPermission(permissions: ["revoke:session:self"])
  revokeAllSessions: Boolean! @hasPermission(permissions: ["revoke:session:self"])
}
```

---

## Summary

The Katabase GraphQL authentication system provides:

✅ **Security:** bcrypt password hashing, JWT with rotation, reuse detection, RBAC  
✅ **User Experience:** Persistent sessions (30 days), automatic refresh, minimal re-authentication  
✅ **Flexibility:** Configurable TTLs, multiple sessions, permission overrides  
✅ **Auditability:** IP/user agent tracking, token family lineage, structured error codes  
✅ **Standards Compliance:** OAuth 2.0 refresh token best practices, JWT (RFC 7519)  
✅ **Scalability:** Stateless access tokens, WebSocket support, future Redis caching

**Key Files:**

- Service: service.go
- JWT: jwt.go
- Refresh: refresh.go
- Middleware: middleware.go
- Schema: root.graphqls
- Config: config.go, config.yml

This implementation balances security, usability, and maintainability while remaining compatible with the broader Katabase GraphQL architecture (see Copilot Instructions).
