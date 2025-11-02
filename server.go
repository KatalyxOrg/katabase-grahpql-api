package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"github.com/rs/cors"
	"github.com/vektah/gqlparser/v2/ast"
	"katalyx.fr/katabasegql/config"
	"katalyx.fr/katabasegql/graph"
	"katalyx.fr/katabasegql/graph/resolver"
	"katalyx.fr/katabasegql/internal/authentication"
	"katalyx.fr/katabasegql/internal/user"
	"katalyx.fr/katabasegql/pkg/errormsg"
	"katalyx.fr/katabasegql/pkg/maps"
)

const defaultPort = "8080"

func main() {
	configuration, err := config.New()

	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	port := configuration.Port

	if port == "" {
		port = defaultPort
	}

	router := chi.NewRouter()

	router.Use(authentication.Middleware(configuration))
	router.Use(cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}).Handler)

	router.Mount("/maps", maps.New(configuration).Routes())

	c := graph.Config{Resolvers: &resolver.Resolver{
		AuthenticationService: authentication.New(configuration),
		MapsService:           maps.New(configuration),
		UsersService:          user.New(configuration),
	}}

	c.Directives.HasPermission = func(ctx context.Context, obj interface{}, next graphql.Resolver, permissions []string) (res interface{}, err error) {
		user := authentication.ForContext(ctx)

		if user == nil {
			return nil, &errormsg.UserAccessDeniedError{}
		}

		permissionSet := make(map[string]struct{}, len(permissions))
		for _, permission := range permissions {
			permissionSet[permission] = struct{}{}
		}

		for _, roles := range user.Roles {
			for _, rolePermission := range roles.Permissions {
				if _, exists := permissionSet[rolePermission.Name]; exists {
					return next(ctx)
				}
			}
		}

		return nil, &errormsg.UserAccessDeniedError{}
	}

	srv := handler.New(graph.NewExecutableSchema(c))

	srv.AddTransport(transport.Websocket{
		KeepAlivePingInterval: 10 * time.Second,
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// Allow all origins for development
				// In production, you should check against allowed origins
				return true
			},
		},
		InitFunc: func(ctx context.Context, initPayload transport.InitPayload) (context.Context, *transport.InitPayload, error) {
			return authentication.WebsocketInitFunc(ctx, initPayload, configuration)
		},
	})
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})
	srv.AddTransport(transport.MultipartForm{})

	srv.SetQueryCache(lru.New[*ast.QueryDocument](1000))

	srv.Use(extension.Introspection{})
	srv.Use(extension.AutomaticPersistedQuery{
		Cache: lru.New[string](100),
	})

	uploadFs := http.FileServer(http.Dir(configuration.Constants.DataPath + "/uploads"))

	router.Handle("/", playground.Handler("GraphQL playground", "/query"))
	router.Handle("/uploads/*", http.StripPrefix("/uploads/", uploadFs))
	router.Handle("/query", srv)

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
