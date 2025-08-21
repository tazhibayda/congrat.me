package domain

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)
import _ "github.com/gin-gonic/gin"

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email        string             `bson:"email"         json:"email"`
	PasswordHash string             `bson:"password_hash" json:"-"`
	Name         string             `bson:"name"          json:"name"`
	Provider     string             `bson:"provider"      json:"provider"`    // "local" | "google"
	ExternalID   string             `bson:"external_id"   json:"external_id"` // Google sub
	Verified     bool               `bson:"verified"      json:"verified"`
	CreatedAt    time.Time          `bson:"created_at"    json:"created_at"`
}
