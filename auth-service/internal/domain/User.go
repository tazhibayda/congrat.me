package domain

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)
import _ "github.com/gin-gonic/gin"

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Email        string             `bson:"email"`
	PasswordHash string             `bson:"password_hash,omitempty"`
	GoogleID     string             `bson:"google_id,omitempty"`
	Name         string             `bson:"name"`
	CreatedAt    time.Time          `bson:"created_at"`
}
