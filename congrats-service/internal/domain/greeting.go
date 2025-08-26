package domain

import "time"

type Greeting struct {
	ID        string    `bson:"_id,omitempty" json:"id"`
	ThreadID  string    `bson:"thread_id" json:"thread_id"`
	Author    string    `bson:"author" json:"author"`   // любое имя или "Anonymous"
	Message   string    `bson:"message" json:"message"` // пока только текст
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}
