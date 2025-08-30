package domain

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Thread struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	OwnerID   primitive.ObjectID `bson:"owner_id" json:"owner_id"` // из access JWT
	Title     string             `bson:"title" json:"title"`
	Slug      string             `bson:"slug" json:"slug"`         // публичный идентификатор
	TTLDays   int                `bson:"ttl_days" json:"ttl_days"` // 0=forever, 1|7|30
	ExpiresAt *time.Time         `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}
