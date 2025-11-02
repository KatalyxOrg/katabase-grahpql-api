package errormsg

type UserEmailAlreadyExistsError struct{}
type UserNotFoundError struct{}
type UserInvalidCredentialsError struct{}
type UserAccessDeniedError struct{}
type RefreshTokenInvalidError struct{}
type RefreshTokenExpiredError struct{}
type RefreshTokenRevokedError struct{}
type RefreshTokenReuseDetectedError struct{}

func (u *UserEmailAlreadyExistsError) Error() string {
	return "user with this email already exists"
}

func (u *UserNotFoundError) Error() string {
	return "user not found"
}

func (u *UserInvalidCredentialsError) Error() string {
	return "invalid credentials"
}

func (u *UserAccessDeniedError) Error() string {
	return "access denied"
}

func (r *RefreshTokenInvalidError) Error() string {
	return "invalid refresh token"
}

func (r *RefreshTokenExpiredError) Error() string {
	return "refresh token expired"
}

func (r *RefreshTokenRevokedError) Error() string {
	return "refresh token revoked"
}

func (r *RefreshTokenReuseDetectedError) Error() string {
	return "refresh token reuse detected - all tokens in family revoked"
}
