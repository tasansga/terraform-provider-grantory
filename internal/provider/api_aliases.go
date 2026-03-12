package provider

import apiclient "github.com/tasansga/terraform-provider-grantory/internal/api/client"

type grantoryClient = apiclient.Client
type apiHost = apiclient.Host
type apiRequest = apiclient.Request
type apiRegister = apiclient.Register
type apiGrant = apiclient.Grant
type apiSchemaDefinition = apiclient.SchemaDefinition
type requestListOptions = apiclient.RequestListOptions
type registerListOptions = apiclient.RegisterListOptions
type apiHostCreatePayload = apiclient.HostCreatePayload
type apiRequestCreatePayload = apiclient.RequestCreatePayload
type apiRequestUpdatePayload = apiclient.RequestUpdatePayload
type apiRegisterCreatePayload = apiclient.RegisterCreatePayload
type apiRegisterUpdatePayload = apiclient.RegisterUpdatePayload
type apiGrantCreatePayload = apiclient.GrantCreatePayload
type apiSchemaDefinitionCreatePayload = apiclient.SchemaDefinitionCreatePayload
