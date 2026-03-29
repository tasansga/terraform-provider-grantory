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
	//go:embed static/water.min.css
	waterCSS []byte

	indexTemplate = template.Must(template.New("index").Funcs(template.FuncMap{
		"labelSummary": labelSummary,
	}).Parse(indexTemplateSource))
	registerTemplate = template.Must(template.New("register").Funcs(template.FuncMap{
		"labelSummary": labelSummary,
		"prettyJSON":   prettyJSON,
	}).Parse(registerTemplateSource))
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
}

type registerPageData struct {
	Namespace string
	Register  storage.Register
	Events    []storage.RegisterEvent
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
