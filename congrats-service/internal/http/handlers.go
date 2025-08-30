package http

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/tazhibayda/congrats-service/internal/queue"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tazhibayda/congrats-service/internal/domain"
	"github.com/tazhibayda/congrats-service/internal/repo"
)

type Handler struct {
	Store *repo.Store
	Pub   *queue.Publisher
}

func NewHandler(store *repo.Store, pub *queue.Publisher) *Handler {
	return &Handler{Store: store, Pub: pub}
}

// простая генерация короткого slug
func newSlug() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
}

// POST /api/congrats/threads  (JWT обязателен)
type createThreadReq struct {
	Title   string `json:"title"`
	TTLDays int    `json:"ttl_days"` // 0|1|7|30
}

// CreateThread @Summary CreateThread thread
// @Tags threads
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param payload body createThreadReq true "title, ttl_days(0|1|7|30)"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Router /api/congrats/threads [post]
func (h *Handler) CreateThread(c *gin.Context) {
	var in createThreadReq
	if err := c.ShouldBindJSON(&in); err != nil || strings.TrimSpace(in.Title) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad payload"})
		return
	}
	if !(in.TTLDays == 0 || in.TTLDays == 1 || in.TTLDays == 7 || in.TTLDays == 30) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ttl must be 0|1|7|30"})
		return
	}
	uid := c.GetString("uid")
	ownerID, err := primitive.ObjectIDFromHex(uid)
	fmt.Println(uid)
	fmt.Println(ownerID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid uid"})
	}
	t := &domain.Thread{
		OwnerID:   ownerID,
		Title:     strings.TrimSpace(in.Title),
		Slug:      newSlug(),
		TTLDays:   in.TTLDays,
		CreatedAt: time.Now().UTC(),
	}
	if in.TTLDays > 0 {
		exp := time.Now().Add(time.Duration(in.TTLDays) * 24 * time.Hour).UTC()
		t.ExpiresAt = &exp
	}
	if err := h.Store.CreateThread(c.Request.Context(), t); err != nil {
		if err == repo.ErrSlugExists {
			c.JSON(http.StatusConflict, gin.H{"error": "slug conflict"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": t.ID, "slug": t.Slug, "expires_at": t.ExpiresAt})
}

// POST /api/congrats/threads/:slug/submit  (публично)
type submitReq struct {
	Author  string `json:"author"`
	Message string `json:"message"`
}

// SubmitGreeting @Summary Submit greeting (public)
// @Tags greetings
// @Accept json
// @Param slug path string true "thread slug"
// @Param payload body submitReq true "author(optional), message"
// @Success 201
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/congrats/threads/{slug}/submit [post]
func (h *Handler) SubmitGreeting(c *gin.Context) {
	slug := c.Param("slug")
	t, err := h.Store.FindThreadBySlug(c.Request.Context(), slug)
	if err != nil || t == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "thread not found"})
		return
	}
	var in submitReq
	if err := c.ShouldBindJSON(&in); err != nil || strings.TrimSpace(in.Message) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message required"})
		return
	}
	author := strings.TrimSpace(in.Author)
	if author == "" {
		author = "Anonymous"
	}
	g := &domain.Greeting{
		ThreadID:  t.ID,
		Author:    author,
		Message:   in.Message,
		CreatedAt: time.Now().UTC(),
	}
	if t.ExpiresAt != nil {
		g.ExpiresAt = t.ExpiresAt
	}
	if err := h.Store.AddGreeting(c.Request.Context(), g); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "save failed"})
		return
	}
	if h.Pub != nil {
		_ = h.Pub.Publish(c.Request.Context(), "congrats.events", "greeting.created",
			map[string]interface{}{"X-Request-ID": c.GetString("X-Request-ID")},
			queue.GreetingCreated{ThreadID: t.ID.Hex(), Slug: t.Slug, Author: author},
		)
	}

	c.Status(http.StatusCreated)
}

// ViewGreetings @Summary View greetings (owner only)
// @Tags greetings
// @Security BearerAuth
// @Param slug path string true "thread slug"
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/congrats/threads/{slug}/view [get]
func (h *Handler) ViewGreetings(c *gin.Context) {
	slug := c.Param("slug")
	t, err := h.Store.FindThreadBySlug(c.Request.Context(), slug)
	if err != nil || t == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "thread not found"})
		return
	}
	if t.OwnerID.Hex() != c.GetString("uid") {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	items, err := h.Store.ListGreetings(c.Request.Context(), t.ID, 100, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"thread":    gin.H{"id": t.ID, "title": t.Title, "slug": t.Slug, "expires_at": t.ExpiresAt},
		"greetings": items,
	})
}
