package http_test

import (
	"bytes"
	"encoding/json"
	"github.com/tazhibayda/auth-service/internal/log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_Register_Login_Me(t *testing.T) {
	env := newTestEnv(t)
	defer env.Close()

	// 1) REGISTER
	regBody := `{"email":"john@example.com","password":"StrongP@ss1","name":"John"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(regBody))
	req.Header.Set("Content-Type", "application/json")
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register code=%d body=%s", w.Code, w.Body.String())
	}

	// 2) LOGIN
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/login",
		bytes.NewBufferString(`{"email":"john@example.com","password":"StrongP@ss1"}`))
	req.Header.Set("Content-Type", "application/json")
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login code=%d body=%s", w.Code, w.Body.String())
	}
	var lr struct{ Access, Refresh string }
	if err := json.Unmarshal(w.Body.Bytes(), &lr); err != nil || lr.Access == "" || lr.Refresh == "" {
		t.Fatalf("login resp parse: %v; body=%s", err, w.Body.String())
	}

	// 3) ME
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Access)
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("me code=%d body=%s", w.Code, w.Body.String())
	}
}

func Test_Refresh_Rotate_And_ReuseDetection(t *testing.T) {
	env := newTestEnv(t)
	defer env.Close()

	// подготовка: user + login
	do := func(method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		env.Router.ServeHTTP(w, req)
		return w
	}
	_ = do("POST", "/api/auth/register", `{"email":"u@e.com","password":"StrongP@ss1","name":"U"}`, nil)
	w := do("POST", "/api/auth/login", `{"email":"u@e.com","password":"StrongP@ss1"}`, nil)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var lr struct{ Access, Refresh string }
	_ = json.Unmarshal(w.Body.Bytes(), &lr)

	// 1) первый refresh -> получаем новый A2/R2
	w = do("POST", "/api/auth/refresh", `{"refresh":"`+lr.Refresh+`"}`, nil)
	if w.Code != 200 {
		t.Fatalf("refresh1: %d %s", w.Code, w.Body.String())
	}
	var r1 struct{ Access, Refresh string }
	_ = json.Unmarshal(w.Body.Bytes(), &r1)
	if r1.Refresh == "" || r1.Access == "" {
		t.Fatal("empty refresh/access after rotation")
	}

	// 2) повторный refresh старым токеном -> reuse_detected => 401
	w = do("POST", "/api/auth/refresh", `{"refresh":"`+lr.Refresh+`"}`, nil)
	if w.Code != 401 {
		t.Fatalf("reuse expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// 3) refresh новым R2 после reuse семьи -> тоже 401
	w = do("POST", "/api/auth/refresh", `{"refresh":"`+r1.Refresh+`"}`, nil)
	if w.Code != 401 {
		t.Fatalf("family must be revoked: got %d %s", w.Code, w.Body.String())
	}
}

func Test_EmailVerify_And_ResetPassword(t *testing.T) {
	env := newTestEnv(t)
	defer env.Close()
	// init zap logger for tests (dev mode)
	if _, err := log.Init(false); err != nil {
		t.Fatalf("log init: %v", err)
	}

	// register -> получим dev verify_token в ответе
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/register",
		bytes.NewBufferString(`{"email":"ver@example.com","password":"StrongP@ss1","name":"V"}`))
	req.Header.Set("Content-Type", "application/json")
	env.Router.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var rr map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &rr)
	vt := rr["verify_token_dev"]
	if vt == "" {
		t.Fatalf("no verify token in dev response")
	}

	// verify
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/auth/verify?token="+vt, nil)
	env.Router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}

	// forgot-password -> dev reset_token в ответе
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/forgot-password",
		bytes.NewBufferString(`{"email":"ver@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	env.Router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("forgot: %d %s", w.Code, w.Body.String())
	}
	var fr map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &fr)
	rt := fr["reset_token_dev"]
	if rt == "" {
		t.Fatalf("no reset token in dev response")
	}

	// reset-password
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/reset-password",
		bytes.NewBufferString(`{"token":"`+rt+`","new_password":"N3wStrongP@ss!"}`))
	req.Header.Set("Content-Type", "application/json")
	env.Router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("reset: %d %s", w.Code, w.Body.String())
	}

	// старые refresh семьи должны быть отозваны — проверим что login новым паролем ок, а старые refresh (если были) не работают;
	// для простоты — просто залогинимся новым паролем:
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/login",
		bytes.NewBufferString(`{"email":"ver@example.com","password":"N3wStrongP@ss!"}`))
	req.Header.Set("Content-Type", "application/json")
	env.Router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("login after reset: %d %s", w.Code, w.Body.String())
	}
}
