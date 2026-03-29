package service

import "errors"

var (
	// Resource and reference errors.
	ErrHostNotFound                      = errors.New("host not found")
	ErrHostAlreadyExists                 = errors.New("host already exists")
	ErrHostUniqueKeyConflict             = errors.New("host unique key already exists")
	ErrRequestNotFound                   = errors.New("request not found")
	ErrRequestAlreadyExists              = errors.New("request already exists")
	ErrRequestUniqueKeyConflict          = errors.New("request unique key already exists")
	ErrGrantNotFound                     = errors.New("grant not found")
	ErrGrantAlreadyExists                = errors.New("grant already exists")
	ErrRegisterNotFound                  = errors.New("register not found")
	ErrRegisterAlreadyExists             = errors.New("register already exists")
	ErrRegisterUniqueKeyConflict         = errors.New("register unique key already exists")
	ErrRegisterImmutable                 = errors.New("register is immutable")
	ErrSchemaDefinitionNotFound          = errors.New("schema definition not found")
	ErrSchemaDefinitionAlreadyExists     = errors.New("schema definition already exists")
	ErrSchemaDefinitionUniqueKeyConflict = errors.New("schema definition unique key already exists")
	ErrReferencedHostNotFound            = errors.New("referenced host not found")
	ErrReferencedRequestNotFound         = errors.New("referenced request not found")
)
