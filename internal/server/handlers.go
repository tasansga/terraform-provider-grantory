package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"

	apiservice "github.com/tasansga/terraform-provider-grantory/api/service"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func registerHostRoutes(app fiber.Router) {
	handler := hostHandler{}
	group := app.Group("/hosts")
	group.Get("/", handler.list)
	group.Post("/", handler.create)
	group.Get("/:id", handler.get)
	group.Delete("/:id", handler.delete)
	group.Patch("/:id/labels", handler.updateLabels)
}

type hostHandler struct{}

type hostPayload struct {
	UniqueKey string            `json:"unique_key"`
	Labels    map[string]string `json:"labels"`
}

type hostLabelsPayload struct {
	Labels map[string]string `json:"labels"`
}

func logRequestEntry(c *fiber.Ctx, handler string, details map[string]any) {
	fields := logrus.Fields{
		"namespace":   namespaceFromCtx(c),
		"remote_user": c.Get("REMOTE_USER"),
		"handler":     handler,
		"method":      c.Method(),
		"path":        c.Path(),
	}
	for key, value := range details {
		if value != nil {
			fields[key] = value
		}
	}
	level := logrus.InfoLevel
	if status, ok := fields["status"].(int); ok && status >= http.StatusBadRequest {
		level = logrus.ErrorLevel
	}
	entry := logrus.WithFields(fields)
	if level == logrus.ErrorLevel {
		entry.Error("incoming request")
		return
	}
	entry.Info("incoming request")
}

func (h hostHandler) create(c *fiber.Ctx) error {
	var payload hostPayload
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	logRequestEntry(c, "hostHandler.create", map[string]any{"payload": payload})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	host, err := svc.CreateHost(c.Context(), apiservice.HostCreatePayload{UniqueKey: payload.UniqueKey, Labels: payload.Labels})
	if err != nil {
		switch {
		case errors.Is(err, apiservice.ErrHostAlreadyExists):
			return fiber.NewError(fiber.StatusConflict, "host already exists")
		case errors.Is(err, apiservice.ErrHostUniqueKeyConflict):
			return fiber.NewError(fiber.StatusConflict, "host unique key already exists")
		default:
			logrus.WithError(err).WithField("namespace", namespace).Error("create host")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to persist host")
		}
	}

	return c.Status(fiber.StatusCreated).JSON(host)
}

func (h hostHandler) list(c *fiber.Ctx) error {
	logRequestEntry(c, "hostHandler.list", nil)

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	hosts, err := svc.ListHosts(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list hosts")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to list hosts")
	}
	return c.JSON(hosts)
}

func (h hostHandler) get(c *fiber.Ctx) error {
	hostID := c.Params("id")
	logRequestEntry(c, "hostHandler.get", map[string]any{"host_id": hostID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	host, err := svc.GetHost(c.Context(), hostID)
	if err != nil {
		if errors.Is(err, apiservice.ErrHostNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "host not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("get host")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to fetch host")
	}
	return c.JSON(host)
}

func (h hostHandler) delete(c *fiber.Ctx) error {
	hostID := c.Params("id")
	logRequestEntry(c, "hostHandler.delete", map[string]any{"host_id": hostID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	if err := svc.DeleteHost(c.Context(), hostID); err != nil {
		if errors.Is(err, apiservice.ErrHostNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "host not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("delete host")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to delete host")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h hostHandler) updateLabels(c *fiber.Ctx) error {
	var payload hostLabelsPayload
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if payload.Labels == nil {
		return fiber.NewError(fiber.StatusBadRequest, "labels is required")
	}

	hostID := c.Params("id")
	logRequestEntry(c, "hostHandler.updateLabels", map[string]any{"host_id": hostID, "payload": payload})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	updated, err := svc.UpdateHostLabels(c.Context(), hostID, payload.Labels)
	if err != nil {
		if errors.Is(err, apiservice.ErrHostNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "host not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("update host labels")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to update host")
	}
	return c.JSON(updated)
}

func registerRequestRoutes(app fiber.Router) {
	handler := requestHandler{}
	group := app.Group("/requests")
	group.Get("/", handler.list)
	group.Post("/", handler.create)
	group.Get("/:id", handler.get)
	group.Patch("/:id", handler.update)
	group.Delete("/:id", handler.delete)
}

func registerRegisterRoutes(app fiber.Router) {
	handler := registerHandler{}
	group := app.Group("/registers")
	group.Get("/", handler.list)
	group.Post("/", handler.create)
	group.Get("/:id", handler.get)
	group.Get("/:id/events", handler.listEvents)
	group.Patch("/:id", handler.update)
	group.Delete("/:id", handler.delete)
}

func registerSchemaDefinitionRoutes(app fiber.Router) {
	handler := schemaDefinitionHandler{}
	group := app.Group("/schema-definitions")
	group.Get("/", handler.list)
	group.Post("/", handler.create)
	group.Get("/:id", handler.get)
	group.Patch("/:id/labels", handler.updateLabels)
	group.Delete("/:id", handler.delete)
}

type requestHandler struct{}

type requestCreatePayload struct {
	HostID                    string            `json:"host_id"`
	RequestSchemaDefinitionID string            `json:"request_schema_definition_id"`
	GrantSchemaDefinitionID   string            `json:"grant_schema_definition_id"`
	UniqueKey                 string            `json:"unique_key"`
	Payload                   map[string]any    `json:"payload"`
	Labels                    map[string]string `json:"labels"`
}

type requestUpdatePayload struct {
	Labels *map[string]string `json:"labels"`
}

type schemaDefinitionHandler struct{}

type schemaDefinitionCreatePayload struct {
	UniqueKey string            `json:"unique_key"`
	Schema    json.RawMessage   `json:"schema"`
	Labels    map[string]string `json:"labels"`
}

type schemaDefinitionLabelsPayload struct {
	Labels map[string]string `json:"labels"`
}

func (h requestHandler) create(c *fiber.Ctx) error {
	var payload requestCreatePayload
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if payload.HostID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "host_id is required")
	}

	logRequestEntry(c, "requestHandler.create", map[string]any{
		"host_id":                      payload.HostID,
		"request_schema_definition_id": payload.RequestSchemaDefinitionID,
		"grant_schema_definition_id":   payload.GrantSchemaDefinitionID,
		"unique_key":                   payload.UniqueKey,
		"payload":                      payload.Payload,
		"labels":                       payload.Labels,
	})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	created, err := svc.CreateRequest(c.Context(), apiservice.RequestCreatePayload{
		HostID:                    payload.HostID,
		RequestSchemaDefinitionID: payload.RequestSchemaDefinitionID,
		GrantSchemaDefinitionID:   payload.GrantSchemaDefinitionID,
		UniqueKey:                 payload.UniqueKey,
		Payload:                   payload.Payload,
		Labels:                    payload.Labels,
	})
	if err != nil {
		switch {
		case errors.Is(err, apiservice.ErrRequestAlreadyExists):
			return fiber.NewError(fiber.StatusConflict, "request already exists")
		case errors.Is(err, apiservice.ErrRequestUniqueKeyConflict):
			return fiber.NewError(fiber.StatusConflict, "request unique key already exists")
		case errors.Is(err, apiservice.ErrReferencedHostNotFound):
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("host %s not found", payload.HostID))
		case errors.Is(err, apiservice.ErrSchemaDefinitionNotFound):
			missingID, resolveErr := resolveMissingRequestSchemaID(c.Context(), svc, payload.RequestSchemaDefinitionID, payload.GrantSchemaDefinitionID)
			if resolveErr != nil {
				logrus.WithError(resolveErr).WithField("namespace", namespace).Error("resolve missing schema definition for request")
				return fiber.NewError(fiber.StatusInternalServerError, "unable to load schema definition")
			}
			if missingID != "" {
				return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("schema definition %s not found", missingID))
			}
			return fiber.NewError(fiber.StatusBadRequest, "schema definition not found")
		case isValidationError(err):
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		default:
			logrus.WithError(err).WithField("namespace", namespace).Error("create request")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to persist request")
		}
	}

	return c.Status(fiber.StatusCreated).JSON(created)
}

func (h requestHandler) list(c *fiber.Ctx) error {
	filters, err := parseRequestListFilters(c)
	if err != nil {
		return err
	}

	logRequestEntry(c, "requestHandler.list", map[string]any{"filters": loggableRequestFilters(filters)})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	requests, err := svc.ListRequests(c.Context(), filters)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list requests")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to list requests")
	}

	return c.JSON(requests)
}

func (h requestHandler) get(c *fiber.Ctx) error {
	reqID := c.Params("id")
	logRequestEntry(c, "requestHandler.get", map[string]any{"request_id": reqID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	req, err := svc.GetRequest(c.Context(), reqID)
	if err != nil {
		if errors.Is(err, apiservice.ErrRequestNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "request not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("get request")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to fetch request")
	}

	return c.JSON(req)
}

func (h requestHandler) delete(c *fiber.Ctx) error {
	requestID := c.Params("id")
	logRequestEntry(c, "requestHandler.delete", map[string]any{"request_id": requestID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	if err := svc.DeleteRequest(c.Context(), requestID); err != nil {
		if errors.Is(err, apiservice.ErrRequestNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "request not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("delete request")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to delete request")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func loggableRequestFilters(filters apiservice.RequestListOptions) map[string]any {
	entry := map[string]any{}
	if filters.HasGrant != nil {
		entry["has_grant"] = *filters.HasGrant
	}
	if len(filters.Labels) > 0 {
		entry["labels"] = filters.Labels
	}
	if len(filters.HostLabels) > 0 {
		entry["host_labels"] = filters.HostLabels
	}
	if len(entry) == 0 {
		return nil
	}
	return entry
}

func parseRequestListFilters(c *fiber.Ctx) (apiservice.RequestListOptions, error) {
	query, err := url.ParseQuery(string(c.Context().URI().QueryString()))
	if err != nil {
		return apiservice.RequestListOptions{}, fiber.NewError(fiber.StatusBadRequest, "invalid query parameters")
	}

	filters := apiservice.RequestListOptions{}
	if raw := query.Get("has_grant"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return apiservice.RequestListOptions{}, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("invalid has_grant %q", raw))
		}
		filters.HasGrant = &value
	}

	if filters.Labels, err = parseLabelFilters(query); err != nil {
		return apiservice.RequestListOptions{}, err
	}
	if filters.HostLabels, err = parseHostLabelFilters(query); err != nil {
		return apiservice.RequestListOptions{}, err
	}

	return filters, nil
}

func parseLabelFilters(query url.Values) (map[string]string, error) {
	return parseLabelFiltersWithKey(query, "label")
}

func parseHostLabelFilters(query url.Values) (map[string]string, error) {
	return parseLabelFiltersWithKey(query, "host_label")
}

func parseLabelFiltersWithKey(query url.Values, keyName string) (map[string]string, error) {
	if labelValues, ok := query[keyName]; ok {
		if len(labelValues) > 0 {
			labels := make(map[string]string, len(labelValues))
			for _, raw := range labelValues {
				key, value, found := strings.Cut(raw, "=")
				if !found || key == "" {
					return nil, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("invalid %s filter %q", keyName, raw))
				}
				labels[key] = value
			}
			return labels, nil
		}
	}
	return nil, nil
}

func (h requestHandler) update(c *fiber.Ctx) error {
	var payload requestUpdatePayload
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if payload.Labels == nil {
		return fiber.NewError(fiber.StatusBadRequest, "labels are required")
	}

	reqID := c.Params("id")
	logRequestEntry(c, "requestHandler.update", map[string]any{"request_id": reqID, "labels": payload.Labels})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	updated, err := svc.UpdateRequestLabels(c.Context(), reqID, *payload.Labels)
	if err != nil {
		if errors.Is(err, apiservice.ErrRequestNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "request not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("update request labels")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to update request")
	}
	return c.JSON(updated)
}

type registerHandler struct{}

type registerCreatePayload struct {
	HostID             string            `json:"host_id"`
	SchemaDefinitionID string            `json:"schema_definition_id"`
	UniqueKey          string            `json:"unique_key"`
	Payload            map[string]any    `json:"payload"`
	Mutable            bool              `json:"mutable"`
	Labels             map[string]string `json:"labels"`
}

type registerUpdatePayload struct {
	Payload *map[string]any    `json:"payload"`
	Labels  *map[string]string `json:"labels"`
}

func (h registerHandler) create(c *fiber.Ctx) error {
	var payload registerCreatePayload
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if payload.HostID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "host_id is required")
	}

	logRequestEntry(c, "registerHandler.create", map[string]any{
		"host_id":              payload.HostID,
		"schema_definition_id": payload.SchemaDefinitionID,
		"unique_key":           payload.UniqueKey,
		"payload":              payload.Payload,
		"mutable":              payload.Mutable,
		"labels":               payload.Labels,
	})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	created, err := svc.CreateRegister(c.Context(), apiservice.RegisterCreatePayload{
		HostID:             payload.HostID,
		SchemaDefinitionID: payload.SchemaDefinitionID,
		UniqueKey:          payload.UniqueKey,
		Payload:            payload.Payload,
		Mutable:            payload.Mutable,
		Labels:             payload.Labels,
	})
	if err != nil {
		switch {
		case errors.Is(err, apiservice.ErrRegisterAlreadyExists):
			return fiber.NewError(fiber.StatusConflict, "register already exists")
		case errors.Is(err, apiservice.ErrRegisterUniqueKeyConflict):
			return fiber.NewError(fiber.StatusConflict, "register unique key already exists")
		case errors.Is(err, apiservice.ErrReferencedHostNotFound):
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("host %s not found", payload.HostID))
		case errors.Is(err, apiservice.ErrSchemaDefinitionNotFound):
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("schema definition %s not found", payload.SchemaDefinitionID))
		case isValidationError(err):
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		default:
			logrus.WithError(err).WithField("namespace", namespace).Error("create register")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to persist register")
		}
	}

	return c.Status(fiber.StatusCreated).JSON(created)
}

func (h registerHandler) list(c *fiber.Ctx) error {
	filters, err := parseRegisterListFilters(c)
	if err != nil {
		return err
	}

	logRequestEntry(c, "registerHandler.list", map[string]any{"filters": filters})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	registers, err := svc.ListRegisters(c.Context(), filters)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list registers")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to list registers")
	}

	return c.JSON(registers)
}

func (h registerHandler) get(c *fiber.Ctx) error {
	registerID := c.Params("id")
	logRequestEntry(c, "registerHandler.get", map[string]any{"register_id": registerID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	reg, err := svc.GetRegister(c.Context(), registerID)
	if err != nil {
		if errors.Is(err, apiservice.ErrRegisterNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "register not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("get register")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to fetch register")
	}
	return c.JSON(reg)
}

func (h registerHandler) update(c *fiber.Ctx) error {
	var payload registerUpdatePayload
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if payload.Payload == nil && payload.Labels == nil {
		return fiber.NewError(fiber.StatusBadRequest, "payload and/or labels are required")
	}

	registerID := c.Params("id")
	logRequestEntry(c, "registerHandler.update", map[string]any{"register_id": registerID, "payload": payload.Payload, "labels": payload.Labels})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	updated, err := svc.UpdateRegister(c.Context(), registerID, apiservice.RegisterUpdatePayload{
		Payload: payload.Payload,
		Labels:  payload.Labels,
	})
	if err != nil {
		switch {
		case errors.Is(err, apiservice.ErrRegisterNotFound):
			return fiber.NewError(fiber.StatusNotFound, "register not found")
		case errors.Is(err, apiservice.ErrRegisterImmutable):
			return fiber.NewError(fiber.StatusConflict, "register payload is immutable")
		case isValidationError(err):
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("update register labels")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to update register")
	}

	return c.JSON(updated)
}

func (h registerHandler) listEvents(c *fiber.Ctx) error {
	registerID := c.Params("id")
	logRequestEntry(c, "registerHandler.listEvents", map[string]any{"register_id": registerID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	events, err := svc.ListRegisterEvents(c.Context(), registerID)
	if err != nil {
		if errors.Is(err, apiservice.ErrRegisterNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "register not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("list register events")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to list register events")
	}
	return c.JSON(events)
}

func (h registerHandler) delete(c *fiber.Ctx) error {
	registerID := c.Params("id")
	logRequestEntry(c, "registerHandler.delete", map[string]any{"register_id": registerID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	if err := svc.DeleteRegister(c.Context(), registerID); err != nil {
		if errors.Is(err, apiservice.ErrRegisterNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "register not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("delete register")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to delete register")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func parseRegisterListFilters(c *fiber.Ctx) (apiservice.RegisterListOptions, error) {
	query, err := url.ParseQuery(string(c.Context().URI().QueryString()))
	if err != nil {
		return apiservice.RegisterListOptions{}, fiber.NewError(fiber.StatusBadRequest, "invalid query parameters")
	}
	filters := apiservice.RegisterListOptions{}
	if filters.Labels, err = parseLabelFilters(query); err != nil {
		return apiservice.RegisterListOptions{}, err
	}
	if filters.HostLabels, err = parseHostLabelFilters(query); err != nil {
		return apiservice.RegisterListOptions{}, err
	}
	return filters, nil
}

func (h schemaDefinitionHandler) create(c *fiber.Ctx) error {
	var payload schemaDefinitionCreatePayload
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	logRequestEntry(c, "schemaDefinitionHandler.create", map[string]any{"schema_bytes": len(payload.Schema), "unique_key": payload.UniqueKey, "labels": payload.Labels})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	created, err := svc.CreateSchemaDefinition(c.Context(), apiservice.SchemaDefinitionCreatePayload{
		UniqueKey: payload.UniqueKey,
		Schema:    payload.Schema,
		Labels:    payload.Labels,
	})
	if err != nil {
		switch {
		case errors.Is(err, apiservice.ErrSchemaDefinitionAlreadyExists):
			return fiber.NewError(fiber.StatusConflict, "schema definition already exists")
		case errors.Is(err, apiservice.ErrSchemaDefinitionUniqueKeyConflict):
			return fiber.NewError(fiber.StatusConflict, "schema definition unique key already exists")
		case isValidationError(err):
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		default:
			logrus.WithError(err).WithField("namespace", namespace).Error("create schema definition")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to persist schema definition")
		}
	}

	return c.Status(http.StatusCreated).JSON(created)
}

func (h schemaDefinitionHandler) get(c *fiber.Ctx) error {
	defID := c.Params("id")
	logRequestEntry(c, "schemaDefinitionHandler.get", map[string]any{"schema_definition_id": defID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	def, err := svc.GetSchemaDefinition(c.Context(), defID)
	if err != nil {
		if errors.Is(err, apiservice.ErrSchemaDefinitionNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "schema definition not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("get schema definition")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to fetch schema definition")
	}

	return c.JSON(def)
}

func (h schemaDefinitionHandler) list(c *fiber.Ctx) error {
	logRequestEntry(c, "schemaDefinitionHandler.list", nil)

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	defs, err := svc.ListSchemaDefinitions(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list schema definitions")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to list schema definitions")
	}

	return c.JSON(defs)
}

func (h schemaDefinitionHandler) delete(c *fiber.Ctx) error {
	defID := c.Params("id")
	logRequestEntry(c, "schemaDefinitionHandler.delete", map[string]any{"schema_definition_id": defID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	if err := svc.DeleteSchemaDefinition(c.Context(), defID); err != nil {
		if errors.Is(err, apiservice.ErrSchemaDefinitionNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "schema definition not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("delete schema definition")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to delete schema definition")
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h schemaDefinitionHandler) updateLabels(c *fiber.Ctx) error {
	var payload schemaDefinitionLabelsPayload
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if payload.Labels == nil {
		return fiber.NewError(fiber.StatusBadRequest, "labels is required")
	}

	defID := c.Params("id")
	logRequestEntry(c, "schemaDefinitionHandler.updateLabels", map[string]any{"schema_definition_id": defID, "labels": payload.Labels})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	updated, err := svc.UpdateSchemaDefinitionLabels(c.Context(), defID, payload.Labels)
	if err != nil {
		if errors.Is(err, apiservice.ErrSchemaDefinitionNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "schema definition not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("update schema definition labels")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to update schema definition")
	}

	return c.JSON(updated)
}

func registerGrantRoutes(app fiber.Router) {
	handler := grantHandler{}
	group := app.Group("/grants")
	group.Get("/", handler.list)
	group.Post("/", handler.create)
	group.Get("/:id", handler.get)
	group.Delete("/:id", handler.delete)
}

type grantHandler struct{}

type grantCreatePayload struct {
	RequestID string         `json:"request_id"`
	Payload   map[string]any `json:"payload"`
}

func (h grantHandler) create(c *fiber.Ctx) error {
	var payload grantCreatePayload
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if payload.RequestID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "request_id is required")
	}

	logRequestEntry(c, "grantHandler.create", map[string]any{"request_id": payload.RequestID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	grant, err := svc.CreateGrant(c.Context(), apiservice.GrantCreatePayload{RequestID: payload.RequestID, Payload: payload.Payload})
	if err != nil {
		switch {
		case errors.Is(err, apiservice.ErrGrantAlreadyExists):
			return fiber.NewError(fiber.StatusConflict, "grant already exists")
		case errors.Is(err, apiservice.ErrRequestNotFound), errors.Is(err, apiservice.ErrReferencedRequestNotFound):
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("request %s not found", payload.RequestID))
		case errors.Is(err, apiservice.ErrSchemaDefinitionNotFound):
			return fiber.NewError(fiber.StatusBadRequest, "schema definition not found")
		case isValidationError(err):
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		default:
			logrus.WithError(err).WithField("namespace", namespace).Error("create grant")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to persist grant")
		}
	}

	return c.Status(fiber.StatusCreated).JSON(grant)
}

func (h grantHandler) list(c *fiber.Ctx) error {
	logRequestEntry(c, "grantHandler.list", nil)

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	grants, err := svc.ListGrants(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list grants")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to list grants")
	}
	return c.JSON(grants)
}

func (h grantHandler) get(c *fiber.Ctx) error {
	grantID := c.Params("id")
	logRequestEntry(c, "grantHandler.get", map[string]any{"grant_id": grantID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	grant, err := svc.GetGrant(c.Context(), grantID)
	if err != nil {
		if errors.Is(err, apiservice.ErrGrantNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "grant not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("get grant")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to fetch grant")
	}
	return c.JSON(grant)
}

func (h grantHandler) delete(c *fiber.Ctx) error {
	grantID := c.Params("id")
	logRequestEntry(c, "grantHandler.delete", map[string]any{"grant_id": grantID})

	svc, namespace, err := resolveNamespaceService(c)
	if err != nil {
		return err
	}

	if err := svc.DeleteGrant(c.Context(), grantID); err != nil {
		if errors.Is(err, apiservice.ErrGrantNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "grant not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("delete grant")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to delete grant")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func resolveNamespaceService(c *fiber.Ctx) (*apiservice.Service, string, error) {
	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return nil, namespace, err
	}
	return apiservice.New(newServiceStoreAdapter(store)), namespace, nil
}

func resolveNamespaceStore(c *fiber.Ctx) (storage.Store, string, error) {
	namespace := namespaceFromCtx(c)
	store := storeFromLocals(c.Locals(storeCtxKey))
	if store == nil {
		logrus.WithField("namespace", namespace).Error("namespace store missing")
		return nil, namespace, fiber.NewError(fiber.StatusInternalServerError, "namespace store unavailable")
	}
	return store, namespace, nil
}

func storeFromLocals(value interface{}) storage.Store {
	switch v := value.(type) {
	case storage.Store:
		return v
	case localStore:
		return v.store
	case *localStore:
		return v.store
	default:
		return nil
	}
}

func namespaceFromCtx(c *fiber.Ctx) string {
	if raw := c.Locals(namespaceCtxKey); raw != nil {
		if namespace, ok := raw.(string); ok && namespace != "" {
			return namespace
		}
	}
	return DefaultNamespace
}

func isValidationError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "is required") ||
		strings.Contains(msg, "must be valid json") ||
		strings.Contains(msg, "not valid json schema") ||
		strings.Contains(msg, "does not match schema")
}

func resolveMissingRequestSchemaID(ctx context.Context, svc *apiservice.Service, requestSchemaID, grantSchemaID string) (string, error) {
	if requestSchemaID != "" {
		_, err := svc.GetSchemaDefinition(ctx, requestSchemaID)
		if errors.Is(err, apiservice.ErrSchemaDefinitionNotFound) {
			return requestSchemaID, nil
		}
		if err != nil {
			return "", err
		}
	}
	if grantSchemaID != "" {
		_, err := svc.GetSchemaDefinition(ctx, grantSchemaID)
		if errors.Is(err, apiservice.ErrSchemaDefinitionNotFound) {
			return grantSchemaID, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", nil
}
