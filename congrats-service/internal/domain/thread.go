package domain

import "time"

type Thread struct {
	ID        string     `bson:"_id,omitempty" json:"id"`
	OwnerID   string     `bson:"owner_id" json:"owner_id"` // из access JWT
	Title     string     `bson:"title" json:"title"`
	Slug      string     `bson:"slug" json:"slug"`         // публичный идентификатор
	TTLDays   int        `bson:"ttl_days" json:"ttl_days"` // 0=forever, 1|7|30
	ExpiresAt *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	CreatedAt time.Time  `bson:"created_at" json:"created_at"`
}
