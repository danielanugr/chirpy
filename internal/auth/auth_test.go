package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "Valid password",
			password: "secretpassword123",
			wantErr:  false,
		},
		{
			name:     "Short passsword",
			password: "1234",
			wantErr:  false,
		},
		{
			name:     "Empty password",
			password: "",
			wantErr:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := HashPassword(test.password)

			if (err != nil) != test.wantErr {
				t.Errorf("HashPassword() error := %v, wantErr %v", err, test.wantErr)
				return
			}

			if !test.wantErr {
				if got == "" {
					t.Error("hashPassword() returned empty hash")
				}

				if got == test.password {
					t.Error("HashPassword() returned unhashed password")
				}

				if !strings.Contains(got, "$argon2id$") {
					t.Errorf("HashPassword() hash doesn't look like argon2id format, got: %s", got)
				}
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	knownPassword := "testpassword123"
	hash, err := HashPassword(knownPassword)
	if err != nil {
		t.Fatalf("Failed to create test hash: %v", err)
	}

	tests := []struct {
		name      string
		password  string
		hash      string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "Correct password",
			password:  knownPassword,
			hash:      hash,
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "Wrong password",
			password:  "wrongpassword",
			hash:      hash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "Empty password",
			password:  "",
			hash:      hash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "Invalid hash format",
			password:  knownPassword,
			hash:      "invalid_hash_format",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Empty hash",
			password:  knownPassword,
			hash:      "",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Both empty",
			password:  "",
			hash:      "",
			wantMatch: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckPasswordHash(tt.password, tt.hash)

			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got != tt.wantMatch {
				t.Errorf("CheckPasswordHash() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestHashPasswordConsistency(t *testing.T) {
	password := "consistency_test"

	hash1, err1 := HashPassword(password)
	if err1 != nil {
		t.Fatalf("First hash failed: %v", err1)
	}

	hash2, err2 := HashPassword(password)
	if err2 != nil {
		t.Fatalf("Second hash failed: %v", err2)
	}

	if hash1 == hash2 {
		t.Error("Two hashes of the same password should be different due to salt")
	}

	match1, err1 := CheckPasswordHash(password, hash1)
	if err1 != nil {
		t.Fatalf("First verification failed: %v", err1)
	}
	if !match1 {
		t.Error("First hash should verify against password")
	}

	match2, err2 := CheckPasswordHash(password, hash2)
	if err2 != nil {
		t.Fatalf("Second verification failed: %v", err2)
	}
	if !match2 {
		t.Error("Second hash should verify against password")
	}
}

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	require.NoError(t, err)
	require.NotEmpty(t, token)
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := time.Hour

	// Create a token
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	require.NoError(t, err)

	// Validate the token
	extractedUserID, err := ValidateJWT(token, tokenSecret)
	require.NoError(t, err)
	require.Equal(t, userID, extractedUserID)
}

func TestValidateJWTExpiredToken(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"

	// Create an expired token
	token, err := MakeJWT(userID, tokenSecret, -time.Hour) // Negative duration = already expired
	require.NoError(t, err)

	// Try to validate the expired token
	_, err = ValidateJWT(token, tokenSecret)
	require.Error(t, err)
}

func TestValidateJWTWrongSecret(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	wrongSecret := "wrong-secret"
	expiresIn := time.Hour

	// Create a token
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	require.NoError(t, err)

	// Try to validate with wrong secret
	_, err = ValidateJWT(token, wrongSecret)
	require.Error(t, err)
}
