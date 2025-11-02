package config

import (
	"os"
	"time"

	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"katalyx.fr/katabasegql/pkg/database"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
	"katalyx.fr/katabasegql/pkg/notifications/email"
)

func doesEnvExists(name string) bool {
	_, exists := os.LookupEnv(name)
	return exists
}

type Constants struct {
	// Constants
	Port           string `yaml:"port"`
	DataPath       string `yaml:"dataPath"`
	BaseURL        string `yaml:"baseURL"`
	ApplicationURL string `yaml:"applicationURL"`

	// JWT Configuration
	JWT struct {
		Secret          string        `yaml:"secret"`
		AccessTokenTTL  time.Duration `yaml:"accessTokenTTL"`
		RefreshTokenTTL time.Duration `yaml:"refreshTokenTTL"`
	} `yaml:"jwt"`

	// Maps
	Maps struct {
		ApiKey string `yaml:"apiKey"`
	} `yaml:"maps"`

	// Email
	EmailCredentials struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Email    string `yaml:"email"`
		Password string `yaml:"password"`
	} `yaml:"emailCredentials"`

	// Database
	ConnectionString string `yaml:"connectionString"`
}

type Config struct {
	Constants

	// Repositories
	AddressRepository                dbmodel.AddressRepository
	PermissionRepository             dbmodel.PermissionRepository
	RefreshTokenRepository           dbmodel.RefreshTokenRepository
	RoleRepository                   dbmodel.RoleRepository
	UserPermissionOverrideRepository dbmodel.UserPermissionOverrideRepository
	UserRepository                   dbmodel.UserRepository

	// Services
	EmailService email.EmailService
}

func initViper(configName string) (Constants, error) {
	viper.AddConfigPath(".")
	viper.SetConfigType("yaml")
	viper.SetConfigName(configName)

	err := viper.ReadInConfig()
	if _, ok := err.(viper.ConfigFileNotFoundError); !ok && err != nil {
		return Constants{}, err
	}

	// At this point, the only error would be a missing config file
	if err != nil {
		err = initViperEnv()

		if err != nil {
			return Constants{}, err
		}
	}

	var constants Constants
	err = viper.Unmarshal(&constants)

	return constants, err
}

func initViperEnv() error {
	if !doesEnvExists("PORT") ||
		!doesEnvExists("JWT_SECRET") ||
		!doesEnvExists("JWT_ACCESS_TOKEN_TTL") ||
		!doesEnvExists("JWT_REFRESH_TOKEN_TTL") ||
		!doesEnvExists("DATA_PATH") ||
		!doesEnvExists("BASE_URL") ||
		!doesEnvExists("APPLICATION_URL") ||
		!doesEnvExists("EMAIL_HOST") ||
		!doesEnvExists("EMAIL_PORT") ||
		!doesEnvExists("EMAIL_EMAIL") ||
		!doesEnvExists("EMAIL_PASSWORD") ||
		!doesEnvExists("CONNECTION_STRING") {
		return &MissingEnvVariableError{}
	}

	viper.SetDefault("port", os.Getenv("PORT"))
	viper.SetDefault("jwt.secret", os.Getenv("JWT_SECRET"))
	viper.SetDefault("jwt.accessTokenTTL", os.Getenv("JWT_ACCESS_TOKEN_TTL"))
	viper.SetDefault("jwt.refreshTokenTTL", os.Getenv("JWT_REFRESH_TOKEN_TTL"))
	viper.SetDefault("dataPath", os.Getenv("DATA_PATH"))
	viper.SetDefault("baseURL", os.Getenv("BASE_URL"))
	viper.SetDefault("applicationURL", os.Getenv("APPLICATION_URL"))
	viper.SetDefault("emailCredentials.host", os.Getenv("EMAIL_HOST"))
	viper.SetDefault("emailCredentials.port", os.Getenv("EMAIL_PORT"))
	viper.SetDefault("emailCredentials.email", os.Getenv("EMAIL_EMAIL"))
	viper.SetDefault("emailCredentials.password", os.Getenv("EMAIL_PASSWORD"))
	viper.SetDefault("connectionString", os.Getenv("CONNECTION_STRING"))

	return nil
}

func New() (*Config, error) {
	config := Config{}

	constants, err := initViper("config")

	if err != nil {
		return nil, err
	}

	config.Constants = constants

	// Database
	databaseSession, err := gorm.Open(postgres.Open(config.ConnectionString), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	database.Migrate(databaseSession)

	config.AddressRepository = dbmodel.NewAddressRepository(databaseSession)
	config.PermissionRepository = dbmodel.NewPermissionRepository(databaseSession)
	config.RefreshTokenRepository = dbmodel.NewRefreshTokenRepository(databaseSession)
	config.RoleRepository = dbmodel.NewRoleRepository(databaseSession)
	config.UserPermissionOverrideRepository = dbmodel.NewUserPermissionOverrideRepository(databaseSession)
	config.UserRepository = dbmodel.NewUserRepository(databaseSession)

	// Set default JWT TTLs if not configured
	if config.Constants.JWT.AccessTokenTTL == 0 {
		config.Constants.JWT.AccessTokenTTL = 30 * time.Minute
	}
	if config.Constants.JWT.RefreshTokenTTL == 0 {
		config.Constants.JWT.RefreshTokenTTL = 30 * 24 * time.Hour // 30 days
	}

	// Email
	config.EmailService = email.NewEmailService(
		constants.DataPath+"/emails",
		email.Credentials{
			Host:     constants.EmailCredentials.Host,
			Port:     constants.EmailCredentials.Port,
			Email:    constants.EmailCredentials.Email,
			Password: constants.EmailCredentials.Password,
		},
	)

	return &config, nil
}
