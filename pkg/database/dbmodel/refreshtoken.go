package dbmodel

import (
	"context"
	"time"

	"gorm.io/gorm"
)

type RefreshToken struct {
	gorm.Model

	UserID uint `gorm:"not null;index"`
	User   User `gorm:"foreignKey:UserID"`

	TokenHash string `gorm:"not null;unique;index"`
	FamilyID  string `gorm:"not null;index"`

	ExpiresAt  time.Time `gorm:"not null"`
	RevokedAt  *time.Time
	LastUsedAt *time.Time

	UserAgent string
	IPAddress string
}

type RefreshTokenRepository interface {
	Create(token *RefreshToken) (*RefreshToken, error)
	FindByTokenHash(tokenHash string) (*RefreshToken, error)
	FindByTokenHashIncludingRevoked(tokenHash string) (*RefreshToken, error) // For reuse detection
	FindByFamilyID(familyID string) ([]*RefreshToken, error)
	RevokeByFamilyID(familyID string) error
	RevokeByID(id uint) error
	UpdateLastUsed(id uint) error
	DeleteExpired() error
}

type refreshTokenRepository struct {
	db *gorm.DB
}

func NewRefreshTokenRepository(db *gorm.DB) RefreshTokenRepository {
	return &refreshTokenRepository{db: db}
}

func (r *refreshTokenRepository) Create(token *RefreshToken) (*RefreshToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.WithContext(ctx)

	err := tx.Create(token).Error

	if err != nil {
		return nil, err
	}

	return token, nil
}

func (r *refreshTokenRepository) FindByTokenHash(tokenHash string) (*RefreshToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var token RefreshToken
	tx := r.db.WithContext(ctx).Model(&token)

	err := tx.Where("token_hash = ? AND revoked_at IS NULL", tokenHash).First(&token).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}

		return nil, err
	}

	return &token, nil
}

// FindByTokenHashIncludingRevoked finds a token by its hash, including revoked tokens (for reuse detection)
func (r *refreshTokenRepository) FindByTokenHashIncludingRevoked(tokenHash string) (*RefreshToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var token RefreshToken
	tx := r.db.WithContext(ctx).Model(&token)

	err := tx.Where("token_hash = ?", tokenHash).First(&token).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}

		return nil, err
	}

	return &token, nil
}

func (r *refreshTokenRepository) FindByFamilyID(familyID string) ([]*RefreshToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var tokens []*RefreshToken
	tx := r.db.WithContext(ctx).Model(&RefreshToken{})

	err := tx.Where("family_id = ?", familyID).Find(&tokens).Error

	if err != nil {
		return nil, err
	}

	return tokens, nil
}

func (r *refreshTokenRepository) RevokeByFamilyID(familyID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.WithContext(ctx)

	now := time.Now()
	result := tx.Model(&RefreshToken{}).Where("family_id = ? AND revoked_at IS NULL", familyID).Update("revoked_at", now)

	return result.Error
}

func (r *refreshTokenRepository) RevokeByID(id uint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.WithContext(ctx)

	now := time.Now()
	err := tx.Model(&RefreshToken{}).Where("id = ?", id).Update("revoked_at", now).Error

	return err
}

func (r *refreshTokenRepository) UpdateLastUsed(id uint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.WithContext(ctx)

	now := time.Now()
	err := tx.Model(&RefreshToken{}).Where("id = ?", id).Update("last_used_at", now).Error

	return err
}

func (r *refreshTokenRepository) DeleteExpired() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.WithContext(ctx)

	err := tx.Where("expires_at < ?", time.Now()).Delete(&RefreshToken{}).Error

	return err
}
