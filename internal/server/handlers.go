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
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"

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
	Labels map[string]string `json:"labels"`
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

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	host, err := store.CreateHost(c.Context(), storage.Host{
		Labels: payload.Labels,
	})
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrHostAlreadyExists):
			return fiber.NewError(fiber.StatusConflict, "host already exists")
		default:
			logrus.WithError(err).WithField("namespace", namespace).Error("create host")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to persist host")
		}
	}

	return c.Status(fiber.StatusCreated).JSON(host)
}

func (h hostHandler) list(c *fiber.Ctx) error {
	logRequestEntry(c, "hostHandler.list", nil)

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	hosts, err := store.ListHosts(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list hosts")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to list hosts")
	}
	return c.JSON(hosts)
}

func (h hostHandler) get(c *fiber.Ctx) error {
	hostID := c.Params("id")
	logRequestEntry(c, "hostHandler.get", map[string]any{"host_id": hostID})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	host, err := store.GetHost(c.Context(), hostID)
	if err != nil {
		if errors.Is(err, storage.ErrHostNotFound) {
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

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	if err := store.DeleteHost(c.Context(), hostID); err != nil {
		if errors.Is(err, storage.ErrHostNotFound) {
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
	logRequestEntry(c, "hostHandler.updateLabels", map[string]any{
		"host_id": hostID,
		"payload": payload,
	})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	if err := store.UpdateHostLabels(c.Context(), hostID, payload.Labels); err != nil {
		if errors.Is(err, storage.ErrHostNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "host not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("update host labels")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to update host")
	}

	updated, err := store.GetHost(c.Context(), hostID)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("fetch host after labels update")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to return host")
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
	group.Patch("/:id", handler.update)
	group.Delete("/:id", handler.delete)
}

type requestHandler struct{}

type requestResponse struct {
	storage.Request
	Grant   map[string]any `json:"grant"`
	GrantID string         `json:"grant_id,omitempty"`
}

type requestCreatePayload struct {
	HostID  string            `json:"host_id"`
	Payload map[string]any    `json:"payload"`
	Labels  map[string]string `json:"labels"`
}

type requestUpdatePayload struct {
	Labels *map[string]string `json:"labels"`
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
		"host_id": payload.HostID,
		"payload": payload.Payload,
		"labels":  payload.Labels,
	})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	req := storage.Request{
		HostID:  payload.HostID,
		Payload: payload.Payload,
		Labels:  payload.Labels,
	}
	created, err := store.CreateRequest(c.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrRequestAlreadyExists):
			return fiber.NewError(fiber.StatusConflict, "request already exists")
		case errors.Is(err, storage.ErrReferencedHostNotFound):
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("host %s not found", payload.HostID))
		default:
			logrus.WithError(err).WithField("namespace", namespace).Error("create request")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to persist request")
		}
	}

	loaded, err := store.GetRequest(c.Context(), created.ID)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("fetch request after create")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to return request")
	}

	response, err := buildRequestResponse(c.Context(), store, loaded)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).WithField("request_id", created.ID).Error("prepare request response")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to include grant data")
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

func (h requestHandler) list(c *fiber.Ctx) error {
	filters, err := parseRequestListFilters(c)
	if err != nil {
		return err
	}

	logRequestEntry(c, "requestHandler.list", map[string]any{"filters": loggableRequestFilters(filters)})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	requests, err := store.ListRequests(c.Context(), &filters)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list requests")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to list requests")
	}

	responses := make([]requestResponse, 0, len(requests))
	for _, req := range requests {
		response, err := buildRequestResponse(c.Context(), store, req)
		if err != nil {
			logrus.WithError(err).WithField("namespace", namespace).WithField("request_id", req.ID).Error("prepare request response")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to include grant data")
		}
		responses = append(responses, response)
	}

	return c.JSON(responses)
}

func (h requestHandler) get(c *fiber.Ctx) error {
	reqID := c.Params("id")
	logRequestEntry(c, "requestHandler.get", map[string]any{"request_id": reqID})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	req, err := store.GetRequest(c.Context(), reqID)
	if err != nil {
		if errors.Is(err, storage.ErrRequestNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "request not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("get request")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to fetch request")
	}

	response, err := buildRequestResponse(c.Context(), store, req)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).WithField("request_id", req.ID).Error("prepare request response")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to include grant data")
	}
	return c.JSON(response)
}

func (h requestHandler) delete(c *fiber.Ctx) error {
	requestID := c.Params("id")
	logRequestEntry(c, "requestHandler.delete", map[string]any{"request_id": requestID})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	if err := store.DeleteRequest(c.Context(), requestID); err != nil {
		if errors.Is(err, storage.ErrRequestNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "request not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("delete request")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to delete request")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func loggableRequestFilters(filters storage.RequestListFilters) map[string]any {
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

func parseRequestListFilters(c *fiber.Ctx) (storage.RequestListFilters, error) {
	query, err := url.ParseQuery(string(c.Context().URI().QueryString()))
	if err != nil {
		return storage.RequestListFilters{}, fiber.NewError(fiber.StatusBadRequest, "invalid query parameters")
	}

	filters := storage.RequestListFilters{}
	if raw := query.Get("has_grant"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return storage.RequestListFilters{}, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("invalid has_grant %q", raw))
		}
		filters.HasGrant = &value
	}

	if filters.Labels, err = parseLabelFilters(query); err != nil {
		return storage.RequestListFilters{}, err
	}
	if filters.HostLabels, err = parseHostLabelFilters(query); err != nil {
		return storage.RequestListFilters{}, err
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
func applyRequestFilters(requests []storage.Request, filters storage.RequestListFilters) []storage.Request {
	var filtered []storage.Request
	for _, req := range requests {
		if filters.HasGrant != nil && req.HasGrant != *filters.HasGrant {
			continue
		}
		if !matchesLabelFilters(req.Labels, filters.Labels) {
			continue
		}
		filtered = append(filtered, req)
	}
	return filtered
}

func matchesLabelFilters(labels map[string]string, filters map[string]string) bool {
	if len(filters) == 0 {
		return true
	}
	if len(labels) == 0 {
		return false
	}
	for key, expected := range filters {
		if labels[key] != expected {
			return false
		}
	}
	return true
}

func buildRequestResponse(ctx context.Context, store *storage.Store, req storage.Request) (requestResponse, error) {
	resp := requestResponse{Request: req}
	grant, found, err := store.GetLatestGrantForRequest(ctx, req.ID)
	if err != nil {
		return resp, fmt.Errorf("fetch applied grant: %w", err)
	}
	if !found {
		return resp, nil
	}
	payload, err := decodeGrantPayload(grant.Payload)
	if err != nil {
		return resp, fmt.Errorf("decode grant payload for request %s: %w", req.ID, err)
	}
	grantPayload := map[string]any{
		"grant_id":   grant.ID,
		"created_at": grant.CreatedAt.Format(time.RFC3339Nano),
		"updated_at": grant.UpdatedAt.Format(time.RFC3339Nano),
	}
	if payload != nil {
		grantPayload["payload"] = payload
	} else {
		grantPayload["payload"] = nil
	}
	resp.Grant = grantPayload
	resp.GrantID = grant.ID
	return resp, nil
}

func decodeGrantPayload(payload []byte) (map[string]any, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
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
	logRequestEntry(c, "requestHandler.update", map[string]any{
		"request_id": reqID,
		"labels":     payload.Labels,
	})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	labels := map[string]string(nil)
	if payload.Labels != nil {
		labels = *payload.Labels
	}

	if err := store.UpdateRequestLabels(c.Context(), reqID, labels); err != nil {
		if errors.Is(err, storage.ErrRequestNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "request not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("update request labels")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to update request")
	}

	updated, err := store.GetRequest(c.Context(), reqID)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("fetch request after update")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to return request")
	}

	response, err := buildRequestResponse(c.Context(), store, updated)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).WithField("request_id", updated.ID).Error("prepare request response")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to include grant data")
	}
	return c.JSON(response)
}

type registerHandler struct{}

type registerCreatePayload struct {
	HostID  string            `json:"host_id"`
	Payload map[string]any    `json:"payload"`
	Labels  map[string]string `json:"labels"`
}

type registerUpdatePayload struct {
	Labels *map[string]string `json:"labels"`
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
		"host_id": payload.HostID,
		"payload": payload.Payload,
		"labels":  payload.Labels,
	})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	reg := storage.Register{
		HostID:  payload.HostID,
		Payload: payload.Payload,
		Labels:  payload.Labels,
	}
	created, err := store.CreateRegister(c.Context(), reg)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrRegisterAlreadyExists):
			return fiber.NewError(fiber.StatusConflict, "register already exists")
		case errors.Is(err, storage.ErrReferencedHostNotFound):
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("host %s not found", payload.HostID))
		default:
			logrus.WithError(err).WithField("namespace", namespace).Error("create register")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to persist register")
		}
	}

	stored, err := store.GetRegister(c.Context(), created.ID)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("fetch register after create")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to return register")
	}

	return c.Status(fiber.StatusCreated).JSON(stored)
}

func (h registerHandler) list(c *fiber.Ctx) error {
	filters, err := parseRegisterListFilters(c)
	if err != nil {
		return err
	}

	logRequestEntry(c, "registerHandler.list", map[string]any{"filters": filters})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	registers, err := store.ListRegisters(c.Context(), &filters)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list registers")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to list registers")
	}

	return c.JSON(registers)
}

func (h registerHandler) get(c *fiber.Ctx) error {
	registerID := c.Params("id")
	logRequestEntry(c, "registerHandler.get", map[string]any{"register_id": registerID})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	reg, err := store.GetRegister(c.Context(), registerID)
	if err != nil {
		if errors.Is(err, storage.ErrRegisterNotFound) {
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
	if payload.Labels == nil {
		return fiber.NewError(fiber.StatusBadRequest, "labels are required")
	}

	registerID := c.Params("id")
	logRequestEntry(c, "registerHandler.update", map[string]any{
		"register_id": registerID,
		"labels":      payload.Labels,
	})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	labels := map[string]string(nil)
	if payload.Labels != nil {
		labels = *payload.Labels
	}

	if err := store.UpdateRegisterLabels(c.Context(), registerID, labels); err != nil {
		if errors.Is(err, storage.ErrRegisterNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "register not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("update register labels")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to update register")
	}

	updated, err := store.GetRegister(c.Context(), registerID)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("fetch register after update")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to return register")
	}
	return c.JSON(updated)
}

func (h registerHandler) delete(c *fiber.Ctx) error {
	registerID := c.Params("id")
	logRequestEntry(c, "registerHandler.delete", map[string]any{"register_id": registerID})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	if err := store.DeleteRegister(c.Context(), registerID); err != nil {
		if errors.Is(err, storage.ErrRegisterNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "register not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("delete register")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to delete register")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func parseRegisterListFilters(c *fiber.Ctx) (storage.RegisterListFilters, error) {
	query, err := url.ParseQuery(string(c.Context().URI().QueryString()))
	if err != nil {
		return storage.RegisterListFilters{}, fiber.NewError(fiber.StatusBadRequest, "invalid query parameters")
	}
	filters := storage.RegisterListFilters{}
	if filters.Labels, err = parseLabelFilters(query); err != nil {
		return storage.RegisterListFilters{}, err
	}
	if filters.HostLabels, err = parseHostLabelFilters(query); err != nil {
		return storage.RegisterListFilters{}, err
	}
	return filters, nil
}

func applyRegisterFilters(registers []storage.Register, filters storage.RegisterListFilters) []storage.Register {
	var filtered []storage.Register
	for _, reg := range registers {
		if !matchesLabelFilters(reg.Labels, filters.Labels) {
			continue
		}
		filtered = append(filtered, reg)
	}
	return filtered
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
	RequestID string          `json:"request_id"`
	Payload   json.RawMessage `json:"payload"`
}

func (h grantHandler) create(c *fiber.Ctx) error {
	var payload grantCreatePayload
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if payload.RequestID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "request_id is required")
	}

	logRequestEntry(c, "grantHandler.create", map[string]any{
		"request_id": payload.RequestID,
	})

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	grant := storage.Grant{
		RequestID: payload.RequestID,
		Payload:   payload.Payload,
	}
	created, err := store.CreateGrant(c.Context(), grant)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrGrantAlreadyExists):
			return fiber.NewError(fiber.StatusConflict, "grant already exists")
		case errors.Is(err, storage.ErrReferencedRequestNotFound):
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("request %s not found", payload.RequestID))
		default:
			logrus.WithError(err).WithField("namespace", namespace).Error("create grant")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to persist grant")
		}
	}

	stored, err := store.GetGrant(c.Context(), created.ID)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("fetch grant after create")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to return grant")
	}
	return c.Status(fiber.StatusCreated).JSON(stored)
}

func (h grantHandler) list(c *fiber.Ctx) error {
	logRequestEntry(c, "grantHandler.list", nil)

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	grants, err := store.ListGrants(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list grants")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to list grants")
	}
	return c.JSON(grants)
}

func (h grantHandler) get(c *fiber.Ctx) error {
	grantID := c.Params("id")
	logRequestEntry(c, "grantHandler.get", map[string]any{"grant_id": grantID})
	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	grant, err := store.GetGrant(c.Context(), grantID)
	if err != nil {
		if errors.Is(err, storage.ErrGrantNotFound) {
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

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	if err := store.DeleteGrant(c.Context(), grantID); err != nil {
		if errors.Is(err, storage.ErrGrantNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "grant not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("delete grant")
		return fiber.NewError(fiber.StatusInternalServerError, "unable to delete grant")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func resolveNamespaceStore(c *fiber.Ctx) (*storage.Store, string, error) {
	namespace := namespaceFromCtx(c)
	store := storeFromLocals(c.Locals(storeCtxKey))
	if store == nil {
		logrus.WithField("namespace", namespace).Error("namespace store missing")
		return nil, namespace, fiber.NewError(fiber.StatusInternalServerError, "namespace store unavailable")
	}
	return store, namespace, nil
}

func storeFromLocals(value interface{}) *storage.Store {
	switch v := value.(type) {
	case *storage.Store:
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
