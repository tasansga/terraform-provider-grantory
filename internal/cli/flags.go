package cli

const (
	FlagBackend                    = "backend"
	FlagServerURL                  = "server-url"
	FlagToken                      = "token"
	FlagUser                       = "user"
	FlagPassword                   = "password"
	EnvBackend                     = "BACKEND"
	EnvServerURL                   = "SERVER"
	EnvToken                       = "TOKEN"
	EnvUser                        = "USER"
	EnvPassword                    = "PASSWORD"
	FlagNamespace                  = "namespace"
	EnvNamespace                   = "NAMESPACE"
	EnvGrantoryControllerServerURL = "GRANTORY_CONTROLLER_SERVER"
	EnvGrantoryControllerToken     = "GRANTORY_CONTROLLER_TOKEN"
	EnvGrantoryControllerUser      = "GRANTORY_CONTROLLER_USER"
	EnvGrantoryControllerPassword  = "GRANTORY_CONTROLLER_PASSWORD"
	EnvGrantoryControllerNamespace               = "GRANTORY_CONTROLLER_NAMESPACE"
	EnvGrantoryControllerLogLevel                = "GRANTORY_CONTROLLER_LOG_LEVEL"
	FlagLogLevel                                 = "log-level"
	FlagAutoCreateHost                           = "auto-create-host"
	FlagAutoHostName                             = "auto-host-name"
	FlagAutoHostSecret                           = "auto-host-secret"
	FlagAutoHostSecretNamespace                  = "auto-host-secret-namespace"
	EnvGrantoryControllerAutoCreateHost          = "GRANTORY_CONTROLLER_AUTO_CREATE_HOST"
	EnvGrantoryControllerAutoHostName            = "GRANTORY_CONTROLLER_AUTO_HOST_NAME"
	EnvGrantoryControllerAutoHostSecret          = "GRANTORY_CONTROLLER_AUTO_HOST_SECRET"
	EnvGrantoryControllerAutoHostSecretNamespace = "GRANTORY_CONTROLLER_AUTO_HOST_SECRET_NAMESPACE"
	FlagPrivateKeyFile                           = "private-key-file"
	EnvPrivateKeyFile              = "PRIVATE_KEY_FILE"
	FlagAllowDirectRaftMutation    = "allow-direct-raft-mutation"
	EnvAllowDirectRaftMutation     = "GRANTORY_ALLOW_DIRECT_RAFT_MUTATION"
)

type backendMode string

const (
	backendModeDirect backendMode = "direct"
	backendModeAPI    backendMode = "api"
)

const (
	BackendModeDirect = backendModeDirect
	BackendModeAPI    = backendModeAPI
)
