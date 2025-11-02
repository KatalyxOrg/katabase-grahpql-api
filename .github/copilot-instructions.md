## Project Overview

This is **Katabase GraphQL API** - the foundational template for all Katalyx GraphQL API projects. It provides a production-ready, opinionated architecture for building scalable GraphQL APIs with Go, featuring authentication, authorization (RBAC), database management, and GraphQL code generation.

## Architecture Guidelines

- **Language/Frameworks:** Go, gqlgen for GraphQL, PostgreSQL, Docker.
- **API Surface:** GraphQL over HTTPS and WebSocket (subscriptions) with a single gateway.
- **AuthN:** Email + password; optional OAuth (Google/Microsoft/Apple) for SSO.
- **AuthZ:** JWT (short‑lived access, refresh rotation) + RBAC via GraphQL directive `@hasPermission(permissions: [String!]!)` and service‑level checks.
- **Hosting:** Docker-based deployment; object storage for files with short‑lived signed URLs; no binary files in relational DB.
- **Observability:** Structured JSON logs (trace_id, subject, resource, action), metrics/health checks.

### Repository Structure

```
katabasegql-api/
├── server.go                      # Entrypoint (main.go equivalent)
├── config/                        # Viper-based config, env overrides
│   ├── config.go
│   └── errors.go
├── graph/                         # GraphQL (gqlgen)
│   ├── generated.go
│   ├── model/                     # GraphQL models
│   ├── resolver/                  # Thin resolvers → services
│   └── schema/                    # *.graphqls per domain
├── internal/                      # Application services (Clean Architecture)
│   ├── authentication/            # Password/OAuth, JWT, sessions
│   └── user/                      # Users, profiles
├── pkg/                           # Shared utils (errors, http, crypto, gql)
│   ├── database/                  # DB connection, migrations, repositories
│   │   ├── database.go
│   │   ├── dbmodel/              # GORM models
│   │   └── seed/                 # Database seeds
│   ├── errormsg/                  # Custom error types
│   ├── helper/                    # Utility functions
│   ├── httperrors/                # HTTP error handling
│   ├── maps/                      # Google Maps integration (optional)
│   ├── mocks/                     # Mock implementations
│   └── notifications/             # Email service
│       └── email/
├── docker/                        # Dockerfiles, compose
│   ├── docker-compose.yml         # Development setup
│   ├── docker-compose.prod.yml    # Production setup
│   ├── Dockerfile.prod
│   └── scripts/                   # Backup/restore scripts
├── bruno/                         # API testing (Bruno client)
├── tests/                         # Integration & E2E tests
│   ├── fixtures/                  # Test data factories
│   └── helpers/                   # Test utilities
├── go.mod / go.sum
├── gqlgen.yml                     # GraphQL code generation config
└── config.yml / config.example.yml
```

> **Architecture Principle:** Keep resolvers thin; move business rules (states, validations, business logic) into services with explicit interfaces and unit tests.

## Core Domains & Responsibilities (Template Implementation)

### Implemented (Out-of-the-box)

- **Auth & Users (`internal/authentication`, `internal/user`)**:
  - Password login with JWT (access + refresh tokens)
  - OAuth framework for SSO providers
  - User CRUD with profile management
  - RBAC with role-based and user-specific permission overrides
- **Address Management (`pkg/maps`)**:
  - Google Maps integration for autocomplete and geocoding
  - Normalized address storage with coordinates

### Template Extension Points

When creating a new project from this template, you'll typically add:

- **Domain-Specific Services** in `internal/`:
  - Create new service packages (e.g., `internal/products`, `internal/orders`)
  - Follow the pattern: `service.go`, `service_test.go`, `types.go`
  - Implement repository pattern in `pkg/database/dbmodel/`
- **GraphQL Schema** in `graph/schema/`:
  - Add new `.graphqls` files per domain
  - Define types, inputs, queries, mutations
  - Apply `@hasPermission` directives for protected fields
- **Database Models** in `pkg/database/dbmodel/`:
  - Create GORM models
  - Implement repository interfaces
  - Add migrations and seeds

## GraphQL Layer — Conventions

- **Schema Organization:** One file per domain in `graph/schema/` (e.g., `users.schema.graphqls`, `products.schema.graphqls`)
- **RBAC:** Annotate sensitive fields with `@hasPermission(permissions: [String!]!)`. See [`server.go`](server.go) directive implementation. Always duplicate checks in service layer.
- **Errors:** Use custom error types from [`pkg/errormsg`](pkg/errormsg) and [`pkg/httperrors`](pkg/httperrors).
- **Pagination:** Implement Relay-style connections with cursor-based pagination (see [`graph/model/models_gen.go`](graph/model/models_gen.go) `PageInfo`).
- **Scalars:** `ID` (uint), `Time` (DateTime), `Upload` (file uploads).
- **Subscriptions:** WebSocket for real-time updates (authentication via [`internal/authentication/middleware.go`](internal/authentication/middleware.go) `WebsocketInitFunc`).

### Template Queries/Mutations (Starting Point)

**Current Implementation:**

```graphql
# Auth & Users
mutation login(input: LoginInput!): LoginResult!
mutation refreshToken(refreshToken: String!): LoginResult!
mutation createUser(input: NewUserInput!): User! @hasPermission(permissions: ["create:user"])
mutation updateUser(id: ID!, input: UpdateUserInput!): User! @hasPermission(permissions: ["update:user", "update:user:self"])
query me: User! @hasPermission(permissions: ["read:user:self"])
query users(page: Int, pageSize: Int, sort: SortInput): UserConnection! @hasPermission(permissions: ["read:user"])
query permissions: [Permission!]! @hasPermission(permissions: ["read:permission:all"])
```

**Extension Example (for your project):**

```graphql
# Products (example domain)
query products(first: Int!, after: String, filters: ProductFilters): ProductConnection! @hasPermission(permissions: ["product:read:any"])
query product(id: ID!): Product @hasPermission(permissions: ["product:read:any"])
mutation createProduct(input: CreateProductInput!): Product! @hasPermission(permissions: ["product:create"])
mutation updateProduct(id: ID!, input: UpdateProductInput!): Product! @hasPermission(permissions: ["product:update"])

# Orders (example domain)
query orders(first: Int!, after: String): OrderConnection! @hasPermission(permissions: ["order:read:self"])
mutation createOrder(input: CreateOrderInput!): Order! @hasPermission(permissions: ["order:create"])
subscription onOrderStatus(id: ID!): Order! @hasPermission(permissions: ["order:read:self"])
```

## RBAC Policy — Implementation Guide

### Current System

The RBAC system is implemented via:

1. **Database model:** [`pkg/database/dbmodel`](pkg/database/dbmodel) with `User`, `Role`, `Permission`, `PermissionOverride`.
2. **GraphQL directive:** `@hasPermission(permissions: [String!]!)` defined in [`server.go`](server.go).
3. **Middleware:** [`internal/authentication/middleware.go`](internal/authentication/middleware.go) extracts user from JWT.
4. **Directive logic:** Checks user permissions against role-based and override permissions.

### Permission Format

**Template Format:** `resource:action[:scope]`

**Template Roles (from seed in [`pkg/database/seed/seedv1.go`](pkg/database/seed/seedv1.go)):**

- **USER** (basic authenticated user): `read:user:self`
- **ADMIN** (administrator): `read:user`, `create:user`, `update:user`, `delete:user`, etc.

### Extending Permissions for Your Project

When building on this template:

1. **Define Resource Scopes** based on your domain:

   ```
   product:read:any       # Read all products
   product:create         # Create products
   product:update:self    # Update own products
   order:read:self        # Read own orders
   order:read:any         # Read all orders (admin)
   ```

2. **Create Custom Roles** in your seed files:

   ```go
   // Example: E-commerce roles
   CUSTOMER: product:read:any, order:create, order:read:self
   SELLER: product:create, product:update:self, order:read:self
   ADMIN: product:*, order:*, user:*
   ```

3. **Apply Directives** in your GraphQL schema:
   ```graphql
   type Query {
     products: [Product!]! @hasPermission(permissions: ["product:read:any"])
     myOrders: [Order!]! @hasPermission(permissions: ["order:read:self"])
   }
   ```

### Enhanced RBAC (Future)

For advanced projects, consider implementing:

- Enhanced directive middleware that extracts `sub`, `role`, `scopes`, `policy_version` from JWT
- ALLOW/DENY audit logging with correlation IDs
- Dynamic policy versioning for gradual rollouts

## Error Model

**Current Implementation:**

- Custom error types in [`pkg/errormsg`](pkg/errormsg): `UserAccessDeniedError`, etc.
- HTTP error utilities in [`pkg/httperrors`](pkg/httperrors).

**GraphQL `extensions.code` Convention:**

When adding error handling to your project:

- `UNAUTHENTICATED`: missing/invalid token (also for WebSocket handshake)
- `FORBIDDEN`: RBAC denial
- `VALIDATION_FAILED`: payload/schema validation errors
- `NOT_FOUND`: resource not found
- `CONFLICT`: state conflicts (e.g., duplicate resource)
- `RATE_LIMITED`: exceeded quotas
- `INTEGRATION_ERROR`: upstream service failure/timeouts

**Example Error Implementation:**

```go
// pkg/errormsg/product_errors.go
package errormsg

type ProductNotFoundError struct {
    ProductID string
}

func (e ProductNotFoundError) Error() string {
    return fmt.Sprintf("product %s not found", e.ProductID)
}

func (e ProductNotFoundError) Extensions() map[string]interface{} {
    return map[string]interface{}{
        "code": "NOT_FOUND",
        "productId": e.ProductID,
    }
}
```

## Data & Persistence

**Current Implementation:**

- **PostgreSQL:** GORM models in [`pkg/database/dbmodel`](pkg/database/dbmodel)
- **Migrations:** Manual via [`pkg/database/database.go`](pkg/database/database.go) `Migrate` function
- **Seeds:** Versioned seeds in [`pkg/database/seed`](pkg/database/seed)
- **Repositories:** Embedded in dbmodel files (pattern: `<entity>Repository`)
- **Audit timestamps:** GORM `CreatedAt`, `UpdatedAt`, `DeletedAt` (soft deletes enabled)

**Adding New Entities:**

1. **Create GORM Model** in `pkg/database/dbmodel/`:

   ```go
   // product.go
   type Product struct {
       ID          uint   `gorm:"primarykey"`
       Name        string `gorm:"not null"`
       Description string
       Price       float64 `gorm:"not null"`
       OwnerID     uint   `gorm:"not null"`
       Owner       User   `gorm:"foreignKey:OwnerID"`
       CreatedAt   time.Time
       UpdatedAt   time.Time
       DeletedAt   gorm.DeletedAt `gorm:"index"`
   }

   type ProductRepository struct {
       DB *gorm.DB
   }

   func (r *ProductRepository) Create(product *Product) error {
       return r.DB.Create(product).Error
   }

   func (r *ProductRepository) FindByID(id uint) (*Product, error) {
       var product Product
       err := r.DB.First(&product, id).Error
       return &product, err
   }
   ```

2. **Add Migration** in [`pkg/database/database.go`](pkg/database/database.go):

   ```go
   func (db *Database) Migrate() error {
       return db.Instance.AutoMigrate(
           // ...existing models...
           &dbmodel.Product{},
       )
   }
   ```

3. **Create GraphQL Schema** in `graph/schema/products.schema.graphqls`:

   ```graphql
   type Product {
     id: ID!
     name: String!
     description: String
     price: Float!
     owner: User!
     createdAt: Time!
   }

   input CreateProductInput {
     name: String!
     description: String
     price: Float!
   }

   extend type Query {
     product(id: ID!): Product @hasPermission(permissions: ["product:read:any"])
     products(first: Int!, after: String): ProductConnection! @hasPermission(permissions: ["product:read:any"])
   }

   extend type Mutation {
     createProduct(input: CreateProductInput!): Product! @hasPermission(permissions: ["product:create"])
   }
   ```

4. **Generate & Implement Resolvers:**
   ```bash
   go run github.com/99designs/gqlgen generate
   ```
   Then implement in `graph/resolver/products.resolvers.go`

**Database Best Practices:**

- **Indices:** Add for frequently queried fields and foreign keys
- **Soft Deletes:** Use GORM's `DeletedAt` for reversible deletions
- **Transactions:** Wrap multi-step operations in DB transactions
- **Validation:** Use GORM hooks (`BeforeCreate`, `BeforeUpdate`) for data validation

## Security, Privacy, Compliance

### Transport & Authentication

- **Transport:** HTTPS/WSS only (see [`server.go`](server.go) CORS config); strict CORS; modern TLS
- **Tokens:** JWT from [`internal/authentication`](internal/authentication)
  - Access token: 15–30 min TTL
  - Refresh token: rotation with revocation list
  - Versioned policies in JWT claims

### Data Protection

- **PII:** App‑level encryption for sensitive fields (implement in your domain models)
- **File Storage:** Use signed URLs with short TTL for object storage; never store binaries in DB
- **File Uploads:** EXIF stripping on uploads (implement in future upload handler)
- **Password Security:** bcrypt hashing (see [`internal/authentication`](internal/authentication))

### Audit & Logging

- **Structured Logs:** Use `trace_id`, subject, resource, action, status, reason, timestamp
- **Never Log:** Document binaries, passwords, raw tokens, secrets
- **RBAC Decisions:** Log ALLOW/DENY with context

**Example Audit Log:**

```go
log.Printf(
    "trace_id=%s subject=%s resource=%s action=%s status=%s reason=%s",
    traceID, userID, resourceType, action, "ALLOW", "permission_granted",
)
```

## Testing Strategy

**Current Test Coverage:** 83.8% (115 tests, Grade A-)

### Test Structure

```
tests/
├── fixtures/                   # Test data factories
│   └── users.go
└── helpers/                    # Test utilities
    ├── database.go            # DB setup/teardown
    └── graphql.go             # GraphQL test client

internal/
└── authentication/
    ├── service.go
    ├── service_test.go        # Unit tests
    ├── integration_test.go    # Integration tests
    └── middleware_test.go
```

### Test Types

1. **Unit Tests** (`*_test.go` alongside source):

   - Service layer business logic
   - JWT generation/parsing
   - Password hashing
   - Permission checks

2. **Integration Tests** (`integration_test.go`):

   - Database operations
   - Repository pattern
   - Transaction rollback

3. **GraphQL E2E Tests** (in resolver packages):
   - Full query/mutation cycle
   - Directive behavior
   - WebSocket subscriptions

### Running Tests

```bash
# All tests
go test ./...

# With coverage
go test ./... -cover -coverprofile=coverage.out

# Integration tests only
go test ./... -tags=integration

# View coverage
go tool cover -html=coverage.out
```

### Writing Tests for New Features

**Pattern to follow:**

```go
// internal/myservice/service_test.go
package myservice

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "katalyx.fr/katabasegql/tests/fixtures"
    "katalyx.fr/katabasegql/tests/helpers"
)

func TestMyService_DoSomething(t *testing.T) {
    // Arrange
    db := helpers.SetupTestDatabase(t)
    defer helpers.CleanupTestDatabase(t, db)

    service := &MyService{DB: db}
    user := fixtures.CreateRegularUser(db)

    // Act
    result, err := service.DoSomething(user.ID)

    // Assert
    require.NoError(t, err)
    assert.NotNil(t, result)
    assert.Equal(t, expectedValue, result.Value)
}
```

## Provider Integrations (Template Pattern)

The template provides a framework for integrating external services. Examples:

### Google Maps (Included)

- **Location:** [`pkg/maps`](pkg/maps)
- **Pattern:** Service config struct with methods
- **Usage:** Address autocomplete, geocoding

**Extending with New Providers:**

1. **Create Service Package** in `pkg/` or `internal/`:

   ```
   pkg/
   └── stripe/
       ├── types.go        # Request/response types
       ├── client.go       # HTTP client wrapper
       └── service.go      # Business logic
   ```

2. **Add Configuration** in [`config/config.go`](config/config.go):

   ```go
   type Constants struct {
       // ...existing fields...
       Stripe struct {
           SecretKey string `yaml:"secretKey"`
           WebhookSecret string `yaml:"webhookSecret"`
       } `yaml:"stripe"`
   }
   ```

3. **Implement Idempotency** for webhooks:

   ```go
   // pkg/database/dbmodel/processed_event.go
   type ProcessedEvent struct {
       EventID   string `gorm:"primarykey"`
       Provider  string `gorm:"index"`
       ProcessedAt time.Time
   }
   ```

4. **Add GraphQL Integration:**
   ```graphql
   mutation createPayment(input: PaymentInput!): Payment! @hasPermission(permissions: ["payment:create"])
   query paymentStatus(id: ID!): Payment! @hasPermission(permissions: ["payment:read:self"])
   ```

### Common Provider Patterns

- **OAuth:** See [`internal/authentication`](internal/authentication) for OAuth framework
- **Webhooks:** Verify signatures, store in `processed_events`, retry with backoff
- **API Calls:** Circuit breaker, retries, graceful degradation
- **File Storage:** Signed URLs, metadata in DB only

## CI/CD

**Current Setup:**

- **Docker:** [`docker/docker-compose.yml`](docker/docker-compose.yml) for dev, [`docker/docker-compose.prod.yml`](docker/docker-compose.prod.yml) for production
- **Scripts:** [`docker/scripts/backup.sh`](docker/scripts/backup.sh), [`docker/scripts/restore.sh`](docker/scripts/restore.sh)

**Recommended Pipeline:**

```
test → lint → gqlgen generate → build → migrate (staging) → deploy
```

**GitHub Actions Example:**

```yaml
name: CI/CD

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_USER: test_user
          POSTGRES_PASSWORD: test_password
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: "1.23"
          cache: true

      - name: Install dependencies
        run: go mod download

      - name: Run tests
        run: go test ./... -v -cover -coverprofile=coverage.out
        env:
          DATABASE_URL: postgres://test_user:test_password@localhost:5432/test_db?sslmode=disable

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.out

  build:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'

    steps:
      - uses: actions/checkout@v3

      - name: Build Docker image
        run: docker build -f docker/Dockerfile.prod -t myapp:latest .

      - name: Push to registry
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u ${{ github.actor }} --password-stdin
          docker tag myapp:latest ghcr.io/${{ github.repository }}:latest
          docker push ghcr.io/${{ github.repository }}:latest
```

**Secrets Management:**

- Store in environment variables (see [`config.example.yml`](config.example.yml))
- Never commit `config.yml` (in [`.gitignore`](.gitignore))
- Use encrypted secrets in CI/CD platform
- Rotate regularly (JWT secret, database passwords, API keys)

## Setup & Commands

### Initial Setup

```bash
# Clone template
git clone https://github.com/your-org/katabase-graphql-api my-new-project
cd my-new-project

# Install dependencies
go mod tidy

# Copy config template
cp config.example.yml config.yml
# Edit config.yml with your settings

# Start database
docker compose -f docker/docker-compose.yml up -d db

# Generate GraphQL code
go run github.com/99designs/gqlgen generate

# Run migrations & seeds
go run server.go  # Migrations run on startup
```

### Development

```bash
# Start API (local)
go run server.go

# Run tests
go test ./...

# Run tests with coverage
go test ./... -cover -coverprofile=coverage.out
go tool cover -html=coverage.out

# Generate GraphQL code after schema changes
go run github.com/99designs/gqlgen generate

# Lint
golangci-lint run
```

### Production

```bash
# Build & deploy
docker compose -f docker/docker-compose.prod.yml up -d

# Database backup
docker compose -f docker/docker-compose.prod.yml exec katabasegql-api-backup /scripts/backup.sh

# Database restore
docker compose -f docker/docker-compose.prod.yml exec katabasegql-api-backup /scripts/restore.sh <backup_name>

# View logs
docker compose -f docker/docker-compose.prod.yml logs -f katabasegql-api

# Scale (if using load balancer)
docker compose -f docker/docker-compose.prod.yml up -d --scale katabasegql-api=3
```

## Configuration Management

**All configuration** is managed via [`config/config.go`](config/config.go) and YAML files:

1. **Development:** [`config.yml`](config.yml) (git-ignored)
2. **Example/Template:** [`config.example.yml`](config.example.yml) (committed)
3. **Production:** `config.prod.yml` (deployed separately)

**Environment Variables Override:**

```go
// In config.go, Viper automatically reads from env vars with prefix
viper.SetEnvPrefix("APP")
viper.AutomaticEnv()

// Example: APP_JWT_SECRET overrides jwt.secret in YAML
```

**Adding New Configuration:**

```go
// 1. Add to Constants struct in config/config.go
type Constants struct {
    // ...existing fields...
    MyService struct {
        APIKey string `yaml:"apiKey"`
        Timeout time.Duration `yaml:"timeout"`
    } `yaml:"myService"`
}

// 2. Add to config.example.yml
myService:
  apiKey: "your-api-key-here"
  timeout: 30s

// 3. Access in code
cfg := config.LoadConfig()
apiKey := cfg.MyService.APIKey
```

## Copilot Prompts — Template Usage

When working with this template, use these prompts to accelerate development:

### Schema & Resolvers

- _"Generate gqlgen schema and resolver stubs for [DOMAIN] with Relay pagination and `@hasPermission` on queries."_
- _"Create GraphQL mutations for [ENTITY] CRUD operations with proper permission checks."_
- _"Add WebSocket subscription for [EVENT] with JWT validation at connection init."_

### Services & Business Logic

- _"Implement service in `internal/[DOMAIN]` following the authentication service pattern, with repository pattern and unit tests."_
- _"Create GORM model for [ENTITY] with repository interface in dbmodel, including soft deletes and audit fields."_
- _"Write unit tests for [SERVICE] following the pattern in `internal/authentication/service_test.go`."_

### RBAC & Permissions

- _"Define permission scopes for [RESOURCE] following `resource:action[:scope]` pattern."_
- _"Create seed data for [ROLE] with permissions in `pkg/database/seed/`."_
- _"Add RBAC directive checks to [RESOLVER] and corresponding service layer validation."_

### Integrations

- _"Implement [PROVIDER] integration in `pkg/[PROVIDER]` following the maps service pattern with config and client wrapper."_
- _"Add webhook handler for [PROVIDER] with signature verification and idempotency in `processed_events` table."_
- _"Create OAuth flow for [PROVIDER] using the authentication service framework."_

### Testing

- _"Generate integration test for [FEATURE] using GraphQL test client and database fixtures."_
- _"Create test fixtures for [ENTITY] in `tests/fixtures/` following the users.go pattern."_
- _"Add E2E test for [WORKFLOW] covering happy path and error cases."_

## Guardrails & Checklists

### Before Committing

- [ ] Run `go run github.com/99designs/gqlgen generate` after schema changes
- [ ] All tests passing: `go test ./...`
- [ ] No linting errors: `golangci-lint run`
- [ ] `config.yml` not committed (git-ignored)
- [ ] Updated `config.example.yml` with new fields

### Security

- [ ] Rate‑limit login attempts & WebSocket connections
- [ ] Never log PII, passwords, tokens, or secrets
- [ ] Use bcrypt for password hashing (min cost 10)
- [ ] Apply `@hasPermission` directives on sensitive fields
- [ ] Validate RBAC in both directive and service layer
- [ ] Use signed URLs for file access (short TTL)
- [ ] Implement EXIF stripping on file uploads

### Code Quality

- [ ] Resolvers are thin (delegate to services)
- [ ] Business logic in `internal/*` services
- [ ] Utilities in `pkg/*`
- [ ] Repository pattern for data access
- [ ] Explicit interfaces for services
- [ ] Unit tests for business logic (>80% coverage)
- [ ] Integration tests for database operations
- [ ] Meaningful error messages with context

### Performance

- [ ] Avoid N+1 queries (use dataloaders for complex queries)
- [ ] Index hot database paths
- [ ] Implement backpressure on WebSocket
- [ ] Use pagination for list queries
- [ ] Cache expensive computations
- [ ] Profile database queries in development

### Reliability

- [ ] Idempotent webhook handlers (check `processed_events`)
- [ ] Retries with exponential backoff
- [ ] Circuit breakers for external services
- [ ] Graceful degradation (fallbacks)
- [ ] Database transactions for multi-step operations
- [ ] Health check endpoint returns meaningful status

## Project Customization Guide

### Renaming the Project

1. **Go Module Name:**

   ```bash
   # In go.mod, replace:
   module katalyx.fr/katabasegql
   # With:
   module github.com/yourorg/yourproject
   ```

2. **Import Paths:**

   ```bash
   # Find and replace in all .go files:
   katalyx.fr/katabasegql → github.com/yourorg/yourproject
   ```

3. **Docker Compose:**

   ```yaml
   # In docker/docker-compose.yml and docker/docker-compose.prod.yml
   # Replace service names and network names:
   katabasegql-api → yourproject-api
   katabasegql-api-network → yourproject-network
   ```

4. **Database Names:**
   ```yaml
   # In docker/docker-compose.*.yml
   POSTGRES_DB: katabasegql → yourproject
   ```

### Removing Optional Features

**Google Maps Integration:**

```bash
# If you don't need Maps:
rm -rf pkg/maps/
# Remove from graph/resolver/resolver.go:
# MapsService *maps.Config
# Remove routes in server.go
```

**Email Notifications:**

```bash
# If you don't need email:
rm -rf pkg/notifications/
# Remove from config.go:
# EmailCredentials struct
```

### Adding Your Domain Logic

1. **Define Database Models** in `pkg/database/dbmodel/your_entity.go`
2. **Create GraphQL Schema** in `graph/schema/your_domain.graphqls`
3. **Generate Code:** `go run github.com/99designs/gqlgen generate`
4. **Implement Service** in `internal/your_domain/service.go`
5. **Write Tests** in `internal/your_domain/service_test.go`
6. **Implement Resolvers** in `graph/resolver/your_domain.resolvers.go`

---

**This template is maintained by Katalyx. For issues, contributions, or questions, please refer to the project repository.**

**Last Updated:** December 2024  
**Template Version:** 1.0.0  
**Go Version:** 1.23+  
**gqlgen Version:** 0.17.81
