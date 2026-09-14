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

func renderPageError(err error, namespace, action, fallbackMsg string, extraFields ...logrus.Fields) error {
	if isClusterUnavailableError(err) {
		fe, _ := asFiberError(err)
		return fe
	}
	entry := logrus.WithError(err).WithField("namespace", namespace)
	for _, fields := range extraFields {
		entry = entry.WithFields(fields)
	}
	entry.Error(action)
	return fiber.NewError(http.StatusInternalServerError, fallbackMsg)
}

func (s *Server) handleIndex(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleIndex", nil)

	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}

	reqCounts, err := store.CountRequestsByGrantPresence(c.UserContext())
	if err != nil {
		return renderPageError(err, namespace, "count requests for index", "unable to collect request stats")
	}

	registerCounts, err := store.CountRegisters(c.UserContext())
	if err != nil {
		return renderPageError(err, namespace, "count registers for index", "unable to collect register stats")
	}

	grantCounts, err := store.CountGrants(c.UserContext())
	if err != nil {
		return renderPageError(err, namespace, "count grants for index", "unable to collect grant stats")
	}

	hosts, err := store.ListHosts(c.UserContext())
	if err != nil {
		return renderPageError(err, namespace, "list hosts for index", "unable to list hosts")
	}

	requests, err := store.ListRequests(c.UserContext(), nil)
	if err != nil {
		return renderPageError(err, namespace, "list requests for index", "unable to list requests")
	}

	registers, err := store.ListRegisters(c.UserContext(), nil)
	if err != nil {
		return renderPageError(err, namespace, "list registers for index", "unable to list registers")
	}

	grants, err := store.ListGrants(c.UserContext())
	if err != nil {
		return renderPageError(err, namespace, "list grants for index", "unable to list grants")
	}
	schemaDefinitions, err := store.ListSchemaDefinitions(c.UserContext())
	if err != nil {
		return renderPageError(err, namespace, "list schema definitions for index", "unable to list schema definitions")
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
		return renderPageError(err, namespace, "render index page", "unable to render stats page")
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

	register, err := store.GetRegister(c.UserContext(), registerID)
	if err != nil {
		if errors.Is(err, storage.ErrRegisterNotFound) {
			return fiber.NewError(http.StatusNotFound, "register not found")
		}
		return renderPageError(err, namespace, "load register for detail page", "unable to load register", logrus.Fields{"register_id": registerID})
	}

	events, err := store.ListRegisterEvents(c.UserContext(), registerID)
	if err != nil {
		return renderPageError(err, namespace, "load register events for detail page", "unable to load register events", logrus.Fields{"register_id": registerID})
	}

	data := registerPageData{
		Namespace: namespace,
		Register:  register,
		Events:    events,
	}

	var buf bytes.Buffer
	if err := registerTemplate.Execute(&buf, data); err != nil {
		return renderPageError(err, namespace, "render register page", "unable to render register page")
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

	req, err := store.GetRequest(c.UserContext(), requestID)
	if err != nil {
		if errors.Is(err, storage.ErrRequestNotFound) {
			return fiber.NewError(http.StatusNotFound, "request not found")
		}
		return renderPageError(err, namespace, "load request for detail page", "unable to load request", logrus.Fields{"request_id": requestID})
	}

	var grantPtr *storage.Grant
	if grant, found, err := store.GetGrantForRequest(c.UserContext(), requestID); err != nil {
		return renderPageError(err, namespace, "load grant for request detail page", "unable to load request grant", logrus.Fields{"request_id": requestID})
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
		return renderPageError(err, namespace, "render request page", "unable to render request page")
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

	grant, err := store.GetGrant(c.UserContext(), grantID)
	if err != nil {
		if errors.Is(err, storage.ErrGrantNotFound) {
			return fiber.NewError(http.StatusNotFound, "grant not found")
		}
		return renderPageError(err, namespace, "load grant for detail page", "unable to load grant", logrus.Fields{"grant_id": grantID})
	}

	req, err := store.GetRequest(c.UserContext(), grant.RequestID)
	if err != nil {
		if errors.Is(err, storage.ErrRequestNotFound) {
			return fiber.NewError(http.StatusNotFound, "request not found")
		}
		return renderPageError(err, namespace, "load request for grant detail page", "unable to load grant request", logrus.Fields{"request_id": grant.RequestID})
	}

	data := grantPageData{
		Namespace: namespace,
		Grant:     grant,
		Request:   req,
	}

	var buf bytes.Buffer
	if err := grantTemplate.Execute(&buf, data); err != nil {
		return renderPageError(err, namespace, "render grant page", "unable to render grant page")
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

	def, err := store.GetSchemaDefinition(c.UserContext(), schemaID)
	if err != nil {
		if errors.Is(err, storage.ErrSchemaDefinitionNotFound) {
			return fiber.NewError(http.StatusNotFound, "schema definition not found")
		}
		return renderPageError(err, namespace, "load schema definition for detail page", "unable to load schema definition", logrus.Fields{"schema_definition_id": schemaID})
	}

	data := schemaPageData{
		Namespace: namespace,
		Schema:    def,
	}

	var buf bytes.Buffer
	if err := schemaTemplate.Execute(&buf, data); err != nil {
		return renderPageError(err, namespace, "render schema page", "unable to render schema page")
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
