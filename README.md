# 🚀 Katabase GraphQL API

**Le template de référence pour vos APIs GraphQL chez Katalyx**

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![GraphQL](https://img.shields.io/badge/GraphQL-gqlgen-E10098?style=flat&logo=graphql)](https://gqlgen.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791?style=flat&logo=postgresql)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](https://www.docker.com/)
[![Test Coverage](https://img.shields.io/badge/Coverage-83.8%25-brightgreen)](https://github.com/yourusername/katabase-graphql-api)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📖 À propos

**Katabase GraphQL API** est le template de base pour tous les projets d'API GraphQL développés chez Katalyx. Il fournit une architecture production-ready, avec authentification, autorisation (RBAC), gestion de base de données et génération de code GraphQL.

### 🏢 Katalyx

Chez Katalyx, nous aidons les entreprises B2B à transformer leur écosystème digital en moteur de croissance.

Nous ne sommes pas une agence d'exécution : nous sommes votre partenaire stratégique, capable de concevoir, structurer et piloter votre performance digitale à chaque étape.

---

## ✨ Fonctionnalités

### 🔐 Authentification & Autorisation

- ✅ Authentification par email/mot de passe avec JWT
- ✅ Tokens d'accès (30 min) et de rafraîchissement (30 jours)
- ✅ Rotation automatique des refresh tokens avec détection de réutilisation
- ✅ Framework OAuth prêt pour Google/Microsoft/Apple
- ✅ RBAC (Role-Based Access Control) avec permissions granulaires
- ✅ Directive GraphQL `@hasPermission` pour la protection des ressources
- ✅ Surcharges de permissions par utilisateur

### 🎯 GraphQL & API

- ✅ Serveur GraphQL avec [gqlgen](https://gqlgen.com/)
- ✅ Support WebSocket pour les subscriptions en temps réel
- ✅ Pagination Relay-style avec curseurs
- ✅ Gestion d'erreurs personnalisée avec codes d'extensions
- ✅ Playground GraphQL intégré (développement)
- ✅ Upload de fichiers via GraphQL

### 💾 Base de données

- ✅ PostgreSQL 15+ avec GORM
- ✅ Migrations automatiques au démarrage
- ✅ Système de seeds versionnés
- ✅ Pattern Repository pour l'accès aux données
- ✅ Soft deletes sur tous les modèles
- ✅ Audit automatique (CreatedAt, UpdatedAt)

### 🧪 Tests

- ✅ **83.8% de couverture** (115 tests, Grade A-)
- ✅ Tests unitaires avec mocks (testify, gomock)
- ✅ Tests d'intégration avec base de données réelle
- ✅ Tests E2E GraphQL
- ✅ Fixtures de test réutilisables
- ✅ Database helper pour setup/teardown

### 🛠️ DevOps & Production

- ✅ Configuration via YAML avec surcharge par variables d'environnement
- ✅ Docker & Docker Compose (dev + production)
- ✅ Multi-stage build optimisé
- ✅ Scripts de backup/restore PostgreSQL
- ✅ Health checks et monitoring
- ✅ CORS configuré
- ✅ Rate limiting prêt à l'emploi

### 🔌 Intégrations

- ✅ Google Maps API (autocomplete, geocoding)
- ✅ Service d'emails (SMTP avec templates HTML)
- ✅ Pattern d'intégration pour webhooks
- ✅ Framework pour nouveaux providers

---

## 🏗️ Architecture

```
katabasegql-api/
├── server.go                      # Point d'entrée
├── config/                        # Configuration (Viper)
│   ├── config.go
│   └── errors.go
├── graph/                         # GraphQL (gqlgen)
│   ├── generated.go              # Code généré
│   ├── model/                    # Modèles GraphQL
│   ├── resolver/                 # Resolvers (délèguent aux services)
│   └── schema/                   # Schémas *.graphqls par domaine
├── internal/                      # Services métier (Clean Architecture)
│   ├── authentication/           # Auth, JWT, sessions
│   └── user/                     # Gestion utilisateurs
├── pkg/                          # Utilitaires partagés
│   ├── database/                 # Connexion DB, migrations, repositories
│   │   ├── dbmodel/             # Modèles GORM
│   │   └── seed/                # Seeds versionnés
│   ├── errormsg/                 # Types d'erreurs personnalisés
│   ├── helper/                   # Fonctions utilitaires
│   ├── httperrors/               # Gestion erreurs HTTP
│   ├── maps/                     # Intégration Google Maps
│   ├── mocks/                    # Mocks générés (mockgen)
│   └── notifications/            # Service email
│       └── email/
├── docker/                        # Dockerfiles, compose
│   ├── docker-compose.yml        # Setup développement
│   ├── docker-compose.prod.yml   # Setup production
│   ├── Dockerfile.prod
│   └── scripts/                  # Scripts backup/restore
├── bruno/                         # Tests API (Bruno client)
├── tests/                         # Tests d'intégration & E2E
│   ├── fixtures/                 # Factories de données test
│   └── helpers/                  # Utilitaires de test
├── go.mod / go.sum
├── gqlgen.yml                     # Config génération GraphQL
└── config.yml / config.example.yml
```

### Principes architecturaux

- **Resolvers légers** : délèguent aux services
- **Logique métier** dans `internal/*` avec interfaces explicites
- **Pattern Repository** pour l'accès aux données
- **Tests unitaires** pour la logique métier (>80% couverture)
- **Clean Architecture** : séparation claire des responsabilités

---

## 🚀 Démarrage rapide

### Prérequis

- Go 1.23+
- Docker & Docker Compose
- PostgreSQL 15+ (via Docker ou local)

### Installation

```bash
# 1. Cloner le template
git clone https://github.com/katalyx/katabase-graphql-api mon-projet
cd mon-projet

# 2. Installer les dépendances
go mod tidy

# 3. Copier et configurer
cp config.example.yml config.yml
# Éditer config.yml avec vos paramètres

# 4. Démarrer la base de données
docker compose -f docker/docker-compose.yml up -d db

# 5. Générer le code GraphQL
go run github.com/99designs/gqlgen generate

# 6. Lancer l'API (migrations automatiques au démarrage)
go run server.go
```

L'API est maintenant accessible sur `http://localhost:8080` 🎉

- **GraphQL Playground** : http://localhost:8080/
- **Endpoint GraphQL** : http://localhost:8080/query

---

## 🧪 Tests

```bash
# Tous les tests
go test ./...

# Avec couverture
go test ./... -cover -coverprofile=coverage.out
go tool cover -html=coverage.out

# Tests d'intégration uniquement
go test ./... -tags=integration

# Tests avec détection de race conditions
go test ./... -race
```

**Couverture actuelle** : 83.8% (115 tests, Grade A-)

---

## 📚 Documentation

- **[Guide de test complet](documentation/TESTING_GUIDE.md)** - Stratégies, patterns, best practices
- **[Documentation d'authentification](documentation/AUTHENTICATION_DOCUMENTATION.md)** - JWT, RBAC, OAuth
- **[Implémentation refresh token](documentation/REFRESH_TOKEN_IMPLEMENTATION.md)** - Rotation, sécurité
- **[Instructions Copilot](.github/copilot-instructions.md)** - Guide complet du template

---

## 🔧 Configuration

Toute la configuration se fait via `config.yml` :

```yaml
port: "8080"
dataPath: "./data"
baseURL: "http://localhost:8080"
applicationURL: "http://localhost:3000"

jwt:
  secret: "votre-secret-jwt"
  accessTokenTTL: 30m # Token d'accès : 30 minutes
  refreshTokenTTL: 720h # Token de rafraîchissement : 30 jours

maps:
  apiKey: "votre-cle-google-maps"

emailCredentials:
  host: "smtp.gmail.com"
  port: 587
  email: "votre-email@example.com"
  password: "votre-mot-de-passe"

connectionString: "host=localhost user=postgres password=postgres dbname=katabasegql port=5432 sslmode=disable"
```

---

## 🎯 Cas d'usage

### Créer un nouveau domaine (exemple : Produits)

#### 1. Modèle de base de données

```go
// pkg/database/dbmodel/product.go
package dbmodel

import (
    "time"
    "gorm.io/gorm"
)

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

#### 2. Ajouter la migration

```go
// pkg/database/database.go
func Migrate(database *gorm.DB) {
    database.AutoMigrate(
        // ...modèles existants...
        &dbmodel.Product{},
    )
}
```

#### 3. Schéma GraphQL

```graphql
# graph/schema/products.schema.graphqls
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

#### 4. Générer et implémenter

```bash
# Générer le code
go run github.com/99designs/gqlgen generate

# Implémenter les resolvers dans graph/resolver/products.resolvers.go
# Créer le service dans internal/products/service.go
# Écrire les tests dans internal/products/service_test.go
```

---

## 🔐 RBAC & Permissions

### Format des permissions

```
resource:action[:scope]
```

**Exemples** :

- `user:read:self` - Lire son propre profil
- `user:read:any` - Lire tous les utilisateurs
- `product:create` - Créer des produits
- `order:update:self` - Modifier ses propres commandes

### Utilisation dans GraphQL

```graphql
type Query {
  me: User! @hasPermission(permissions: ["user:read:self"])
  users: [User!]! @hasPermission(permissions: ["user:read:any"])
  products: [Product!]! @hasPermission(permissions: ["product:read:any"])
}

type Mutation {
  createProduct(input: CreateProductInput!): Product! @hasPermission(permissions: ["product:create"])
}
```

### Rôles par défaut

- **USER** : `user:read:self`
- **ADMIN** : Toutes les permissions

### Surcharges de permissions

Les admins peuvent accorder/retirer des permissions spécifiques à des utilisateurs :

```graphql
mutation {
  updatePermissionOverride(input: { userId: 42, permissionId: 7, isGranted: true })
}
```

---

## 🐳 Déploiement

### Développement

```bash
# Démarrer tous les services
docker compose -f docker/docker-compose.yml up -d

# Voir les logs
docker compose -f docker/docker-compose.yml logs -f api

# Arrêter
docker compose -f docker/docker-compose.yml down
```

### Production

```bash
# Build et déploiement
docker compose -f docker/docker-compose.prod.yml up -d

# Backup de la base de données
docker compose -f docker/docker-compose.prod.yml exec katabasegql-api-backup /scripts/backup.sh

# Restauration
docker compose -f docker/docker-compose.prod.yml exec katabasegql-api-backup /scripts/restore.sh <nom_backup>

# Logs
docker compose -f docker/docker-compose.prod.yml logs -f katabasegql-api

# Scaler (avec load balancer)
docker compose -f docker/docker-compose.prod.yml up -d --scale katabasegql-api=3
```

### Variables d'environnement (production)

Créez `docker/config.prod.yml` et remplacez les placeholders dans `docker-compose.prod.yml` :

- `POSTGRES_PASSWORD_PLACEHOLDER`
- `PGADMIN_EMAIL_PLACEHOLDER`
- `PGADMIN_PASSWORD_PLACEHOLDER`

---

## 🛡️ Sécurité

### Checklist

- ✅ HTTPS/WSS uniquement en production
- ✅ CORS configuré strictement
- ✅ Rate limiting sur login et WebSocket
- ✅ Bcrypt pour les mots de passe (coût min 10)
- ✅ JWT avec rotation des refresh tokens
- ✅ Détection de réutilisation des tokens
- ✅ Directive `@hasPermission` + vérifications service
- ✅ Validation RBAC en double (directive + service)
- ✅ Pas de PII dans les logs
- ✅ URLs signées pour les fichiers (TTL court)

### Logs d'audit

```go
log.Printf(
    "trace_id=%s subject=%s resource=%s action=%s status=%s reason=%s",
    traceID, userID, resourceType, action, "ALLOW", "permission_granted",
)
```

---

## 🤝 Contribution

### Workflow

1. Créer une branche : `git checkout -b feature/ma-feature`
2. Faire vos modifications
3. Lancer les tests : `go test ./...`
4. Vérifier le linting : `golangci-lint run`
5. Générer GraphQL si schéma modifié : `go run github.com/99designs/gqlgen generate`
6. Commit et push
7. Créer une Pull Request

### Checklist avant commit

- [ ] Tous les tests passent (`go test ./...`)
- [ ] Pas d'erreurs de linting (`golangci-lint run`)
- [ ] Code GraphQL généré à jour
- [ ] `config.yml` non commité (git-ignoré)
- [ ] `config.example.yml` mis à jour si nouveaux champs

---

## 📊 Stack technique

| Composant           | Technologie | Version |
| ------------------- | ----------- | ------- |
| **Langage**         | Go          | 1.23+   |
| **GraphQL**         | gqlgen      | 0.17.81 |
| **Base de données** | PostgreSQL  | 15+     |
| **ORM**             | GORM        | Latest  |
| **Router**          | Chi         | v5      |
| **JWT**             | golang-jwt  | v3      |
| **Tests**           | testify     | Latest  |
| **Mocks**           | gomock      | v1.6    |
| **Config**          | Viper       | Latest  |
| **Email**           | gomail      | v2      |
| **Conteneurs**      | Docker      | Latest  |

---

## 🆘 Support

### Ressources internes

- Consulter les tests dans `internal/authentication/*_test.go`
- Vérifier les fixtures dans `tests/fixtures/`
- Utiliser les helpers dans `tests/helpers/`

### Questions fréquentes

**Q : Comment ajouter un nouveau provider (Stripe, etc.) ?**

> R : Créez un package dans `pkg/`, ajoutez la config dans `config/config.go`, implémentez l'idempotence pour les webhooks. Voir [Instructions Copilot](.github/copilot-instructions.md#provider-integrations).

**Q : Comment personnaliser les permissions ?**

> R : Définissez vos scopes dans `pkg/database/seed/`, appliquez la directive `@hasPermission` dans vos schémas, vérifiez en double dans les services.

**Q : Puis-je retirer Google Maps ou l'email ?**

> R : Oui, supprimez `pkg/maps/` ou `pkg/notifications/`, retirez du resolver et de la config. Voir [Customization Guide](.github/copilot-instructions.md#removing-optional-features).

---

## 🎓 Ressources d'apprentissage

- [Documentation gqlgen](https://gqlgen.com/)
- [Guide GORM](https://gorm.io/docs/)
- [Best practices Go](https://go.dev/doc/effective_go)
- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

---

## 🚀 Roadmap

### Phase 1 : Template de base ✅

- [x] Authentification JWT
- [x] RBAC complet
- [x] Tests (83.8% couverture)
- [x] Docker production-ready
- [x] Documentation complète

### Phase 2 : En cours

- [ ] Tests upload de fichiers
- [ ] Tests OAuth complet
- [ ] Tests notifications email
- [ ] Dataloaders anti-N+1

### Phase 3 : Prévu

- [ ] Métriques Prometheus
- [ ] Tracing distribué (Jaeger)
- [ ] Cache Redis
- [ ] Rate limiting avancé
- [ ] Pagination offset en plus de curseur

---

## 👥 Équipe

Développé et maintenu par **Katalyx**.

**Contact** : [contact@katalyx.fr](mailto:contact@katalyx.fr)

---

<div align="center">

**[Documentation](.github/copilot-instructions.md)** • **[Tests](documentation/TESTING_GUIDE.md)** • **[Auth](documentation/AUTHENTICATION_DOCUMENTATION.md)**

Made with ❤️ by Katalyx

</div>
