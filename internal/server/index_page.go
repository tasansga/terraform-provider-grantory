package server

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"

	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

var (
	//go:embed templates/index.html
	indexTemplateSource string
	//go:embed templates/register.html
	registerTemplateSource string
	//go:embed templates/request.html
	requestTemplateSource string
	//go:embed templates/grant.html
	grantTemplateSource string
	//go:embed templates/schema.html
	schemaTemplateSource string
	//go:embed static/water.min.css
	waterCSS []byte

	indexTemplate = template.Must(template.New("index").Funcs(template.FuncMap{
		"labelSummary": labelSummary,
	}).Parse(indexTemplateSource))
	registerTemplate = template.Must(template.New("register").Funcs(template.FuncMap{
		"labelSummary": labelSummary,
		"prettyJSON":   prettyJSON,
	}).Parse(registerTemplateSource))
	requestTemplate = template.Must(template.New("request").Funcs(template.FuncMap{
		"labelSummary": labelSummary,
		"prettyJSON":   prettyJSON,
	}).Parse(requestTemplateSource))
	grantTemplate = template.Must(template.New("grant").Funcs(template.FuncMap{
		"prettyJSON": prettyJSON,
	}).Parse(grantTemplateSource))
	schemaTemplate = template.Must(template.New("schema").Funcs(template.FuncMap{
		"labelSummary": labelSummary,
		"prettyJSON":   prettyJSON,
	}).Parse(schemaTemplateSource))
)

type indexPageData struct {
	Namespace            string
	RequestsWithGrant    int64
	RequestsWithoutGrant int64
	TotalRequests        int64
	TotalGrants          int64
	TotalRegisters       int64
	Hosts                []storage.Host
	Requests             []storage.Request
	Grants               []storage.Grant
	Registers            []storage.Register
	SchemaDefinitions    []storage.SchemaDefinition
}

type registerPageData struct {
	Namespace string
	Register  storage.Register
	Events    []storage.RegisterEvent
}

type requestPageData struct {
	Namespace string
	Request   storage.Request
	Grant     *storage.Grant
}

type grantPageData struct {
	Namespace string
	Grant     storage.Grant
	Request   storage.Request
}

type schemaPageData struct {
	Namespace string
	Schema    storage.SchemaDefinition
}

func (s *Server) handleIndex(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleIndex", nil)

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	reqCounts, err := store.CountRequestsByGrantPresence(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("count requests for index")
		return fiber.NewError(http.StatusInternalServerError, "unable to collect request stats")
	}

	registerCounts, err := store.CountRegisters(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("count registers for index")
		return fiber.NewError(http.StatusInternalServerError, "unable to collect register stats")
	}

	grantCounts, err := store.CountGrants(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("count grants for index")
		return fiber.NewError(http.StatusInternalServerError, "unable to collect grant stats")
	}

	hosts, err := store.ListHosts(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list hosts for index")
		return fiber.NewError(http.StatusInternalServerError, "unable to list hosts")
	}

	requests, err := store.ListRequests(c.Context(), nil)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list requests for index")
		return fiber.NewError(http.StatusInternalServerError, "unable to list requests")
	}

	registers, err := store.ListRegisters(c.Context(), nil)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list registers for index")
		return fiber.NewError(http.StatusInternalServerError, "unable to list registers")
	}

	grants, err := store.ListGrants(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list grants for index")
		return fiber.NewError(http.StatusInternalServerError, "unable to list grants")
	}
	schemaDefinitions, err := store.ListSchemaDefinitions(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("list schema definitions for index")
		return fiber.NewError(http.StatusInternalServerError, "unable to list schema definitions")
	}

	data := indexPageData{
		Namespace:            namespace,
		RequestsWithGrant:    reqCounts["with_grant"],
		RequestsWithoutGrant: reqCounts["without_grant"],
		TotalRequests:        reqCounts["with_grant"] + reqCounts["without_grant"],
		TotalGrants:          grantCounts["total"],
		TotalRegisters:       registerCounts["total"],
		Hosts:                hosts,
		Requests:             requests,
		Grants:               grants,
		Registers:            registers,
		SchemaDefinitions:    schemaDefinitions,
	}

	var buf bytes.Buffer
	if err := indexTemplate.Execute(&buf, data); err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("render index page")
		return fiber.NewError(http.StatusInternalServerError, "unable to render stats page")
	}

	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Status(http.StatusOK).Send(buf.Bytes())
}

func (s *Server) handleRegisterPage(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleRegisterPage", nil)

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	registerID := strings.TrimSpace(c.Query("id"))
	if registerID == "" {
		return fiber.NewError(http.StatusBadRequest, "id query parameter is required")
	}

	register, err := store.GetRegister(c.Context(), registerID)
	if err != nil {
		if errors.Is(err, storage.ErrRegisterNotFound) {
			return fiber.NewError(http.StatusNotFound, "register not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).WithField("register_id", registerID).Error("load register for detail page")
		return fiber.NewError(http.StatusInternalServerError, "unable to load register")
	}

	events, err := store.ListRegisterEvents(c.Context(), registerID)
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).WithField("register_id", registerID).Error("load register events for detail page")
		return fiber.NewError(http.StatusInternalServerError, "unable to load register events")
	}

	data := registerPageData{
		Namespace: namespace,
		Register:  register,
		Events:    events,
	}

	var buf bytes.Buffer
	if err := registerTemplate.Execute(&buf, data); err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("render register page")
		return fiber.NewError(http.StatusInternalServerError, "unable to render register page")
	}

	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Status(http.StatusOK).Send(buf.Bytes())
}

func (s *Server) handleRequestPage(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleRequestPage", nil)

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	requestID := strings.TrimSpace(c.Query("id"))
	if requestID == "" {
		return fiber.NewError(http.StatusBadRequest, "id query parameter is required")
	}

	req, err := store.GetRequest(c.Context(), requestID)
	if err != nil {
		if errors.Is(err, storage.ErrRequestNotFound) {
			return fiber.NewError(http.StatusNotFound, "request not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).WithField("request_id", requestID).Error("load request for detail page")
		return fiber.NewError(http.StatusInternalServerError, "unable to load request")
	}

	var grantPtr *storage.Grant
	if grant, found, err := store.GetGrantForRequest(c.Context(), requestID); err != nil {
		logrus.WithError(err).WithField("namespace", namespace).WithField("request_id", requestID).Error("load grant for request detail page")
		return fiber.NewError(http.StatusInternalServerError, "unable to load request grant")
	} else if found {
		grantCopy := grant
		grantPtr = &grantCopy
	}

	data := requestPageData{
		Namespace: namespace,
		Request:   req,
		Grant:     grantPtr,
	}

	var buf bytes.Buffer
	if err := requestTemplate.Execute(&buf, data); err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("render request page")
		return fiber.NewError(http.StatusInternalServerError, "unable to render request page")
	}

	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Status(http.StatusOK).Send(buf.Bytes())
}

func (s *Server) handleGrantPage(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleGrantPage", nil)

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	grantID := strings.TrimSpace(c.Query("id"))
	if grantID == "" {
		return fiber.NewError(http.StatusBadRequest, "id query parameter is required")
	}

	grant, err := store.GetGrant(c.Context(), grantID)
	if err != nil {
		if errors.Is(err, storage.ErrGrantNotFound) {
			return fiber.NewError(http.StatusNotFound, "grant not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).WithField("grant_id", grantID).Error("load grant for detail page")
		return fiber.NewError(http.StatusInternalServerError, "unable to load grant")
	}

	req, err := store.GetRequest(c.Context(), grant.RequestID)
	if err != nil {
		if errors.Is(err, storage.ErrRequestNotFound) {
			return fiber.NewError(http.StatusNotFound, "request not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).WithField("request_id", grant.RequestID).Error("load request for grant detail page")
		return fiber.NewError(http.StatusInternalServerError, "unable to load grant request")
	}

	data := grantPageData{
		Namespace: namespace,
		Grant:     grant,
		Request:   req,
	}

	var buf bytes.Buffer
	if err := grantTemplate.Execute(&buf, data); err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("render grant page")
		return fiber.NewError(http.StatusInternalServerError, "unable to render grant page")
	}

	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Status(http.StatusOK).Send(buf.Bytes())
}

func (s *Server) handleSchemaPage(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleSchemaPage", nil)

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	schemaID := strings.TrimSpace(c.Query("id"))
	if schemaID == "" {
		return fiber.NewError(http.StatusBadRequest, "id query parameter is required")
	}

	def, err := store.GetSchemaDefinition(c.Context(), schemaID)
	if err != nil {
		if errors.Is(err, storage.ErrSchemaDefinitionNotFound) {
			return fiber.NewError(http.StatusNotFound, "schema definition not found")
		}
		logrus.WithError(err).WithField("namespace", namespace).WithField("schema_definition_id", schemaID).Error("load schema definition for detail page")
		return fiber.NewError(http.StatusInternalServerError, "unable to load schema definition")
	}

	data := schemaPageData{
		Namespace: namespace,
		Schema:    def,
	}

	var buf bytes.Buffer
	if err := schemaTemplate.Execute(&buf, data); err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("render schema page")
		return fiber.NewError(http.StatusInternalServerError, "unable to render schema page")
	}

	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Status(http.StatusOK).Send(buf.Bytes())
}

func (s *Server) handleWaterCSS(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleWaterCSS", nil)
	c.Set(fiber.HeaderContentType, "text/css; charset=utf-8")
	c.Set(fiber.HeaderCacheControl, "public, max-age=31536000")
	return c.Status(http.StatusOK).Send(waterCSS)
}

func labelSummary(labels map[string]string) string {
	if len(labels) == 0 {
		return "—"
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, labels[key]))
	}
	return strings.Join(parts, ", ")
}

func prettyJSON(value any) string {
	if value == nil {
		return "{}"
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}
