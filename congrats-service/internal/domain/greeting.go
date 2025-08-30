package domain

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Greeting struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ThreadID  primitive.ObjectID `bson:"thread_id" json:"thread_id"`
	Author    string             `bson:"author" json:"author"`                             // любое имя или "Anonymous"
	Message   string             `bson:"message" json:"message"`                           // пока только текст
	ExpiresAt *time.Time         `bson:"expires_at,omitempty" json:"expires_at,omitempty"` // NEW
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}
