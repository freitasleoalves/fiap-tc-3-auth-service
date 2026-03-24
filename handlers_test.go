package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	app := &App{}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	app.healthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("esperado status 200, got %d", w.Code)
	}

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("esperado status 'ok', got '%s'", body["status"])
	}
}

func TestValidateKeyHandler_NoAuthHeader(t *testing.T) {
	app := &App{}
	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	w := httptest.NewRecorder()

	app.validateKeyHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("esperado status 401, got %d", w.Code)
	}
}

func TestValidateKeyHandler_EmptyBearer(t *testing.T) {
	app := &App{}
	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	req.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()

	app.validateKeyHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("esperado status 401, got %d", w.Code)
	}
}

func TestCreateKeyHandler_WrongMethod(t *testing.T) {
	app := &App{}
	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	w := httptest.NewRecorder()

	app.createKeyHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("esperado status 405, got %d", w.Code)
	}
}

func TestCreateKeyHandler_EmptyName(t *testing.T) {
	app := &App{}
	req := httptest.NewRequest(http.MethodPost, "/admin/keys", strings.NewReader(`{"name":""}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	app.createKeyHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("esperado status 400, got %d", w.Code)
	}
}

func TestCreateKeyHandler_InvalidJSON(t *testing.T) {
	app := &App{}
	req := httptest.NewRequest(http.MethodPost, "/admin/keys", strings.NewReader("invalid"))
	w := httptest.NewRecorder()

	app.createKeyHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("esperado status 400, got %d", w.Code)
	}
}

func TestMasterKeyAuthMiddleware_NoKey(t *testing.T) {
	app := &App{MasterKey: "super-secret"}
	called := false
	handler := app.masterKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("esperado status 403, got %d", w.Code)
	}
	if called {
		t.Error("handler não deveria ter sido chamado")
	}
}

func TestMasterKeyAuthMiddleware_WrongKey(t *testing.T) {
	app := &App{MasterKey: "super-secret"}
	handler := app.masterKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("esperado status 403, got %d", w.Code)
	}
}

func TestMasterKeyAuthMiddleware_CorrectKey(t *testing.T) {
	app := &App{MasterKey: "super-secret"}
	called := false
	handler := app.masterKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer super-secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler deveria ter sido chamado")
	}
	if w.Code != http.StatusOK {
		t.Errorf("esperado status 200, got %d", w.Code)
	}
}
