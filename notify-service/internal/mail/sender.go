package mail

import "log"

type Sender struct{}

func (s *Sender) SendGreeting(to string, subject string, body string) error {
	log.Printf("[MAIL] to=%s subj=%s body=%s", to, subject, body)
	return nil
}
