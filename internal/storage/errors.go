package storage

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrAlreadyExists is returned when a unique constraint violation occurs on primary or unique fields.
	ErrAlreadyExists = errors.New("already exists")
	// ErrKeyAlreadyExists is returned when a unique constraint violation occurs on unique_key.
	ErrKeyAlreadyExists = errors.New("key already exists")
)

// TranslateConstraintError checks for unique constraint violations and translates them
// into standard storage sentinel errors (ErrKeyAlreadyExists or ErrAlreadyExists).
func TranslateConstraintError(err error) error {
	if IsUniqueConstraintError(err) {
		if isUniqueKeyConstraintError(err) ||
			isUniqueHostKeyConstraintError(err) ||
			isUniqueRegisterKeyConstraintError(err) ||
			isUniqueSchemaDefinitionKeyConstraintError(err) {
			return ErrKeyAlreadyExists
		}
		return ErrAlreadyExists
	}
	return err
}

// IsUniqueConstraintError checks whether an error indicates a unique constraint violation
// in either SQLite or PostgreSQL.
func IsUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func isNamedUniqueConstraintError(err error, pgConstraint, sqliteMatch string) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName == pgConstraint
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, sqliteMatch) || strings.Contains(errMsg, pgConstraint)
}

func isUniqueKeyConstraintError(err error) bool {
	return isNamedUniqueConstraintError(err, "requests_unique_key_idx", "requests.unique_key")
}

func isUniqueRegisterKeyConstraintError(err error) bool {
	return isNamedUniqueConstraintError(err, "registers_unique_key_idx", "registers.unique_key")
}

func isUniqueHostKeyConstraintError(err error) bool {
	return isNamedUniqueConstraintError(err, "hosts_unique_key_idx", "hosts.unique_key")
}

func isUniqueSchemaDefinitionKeyConstraintError(err error) bool {
	return isNamedUniqueConstraintError(err, "schema_definitions_unique_key_idx", "schema_definitions.unique_key")
}
