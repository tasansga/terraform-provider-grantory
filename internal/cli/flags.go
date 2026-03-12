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
	EnvGrantoryControllerNamespace = "GRANTORY_CONTROLLER_NAMESPACE"
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
