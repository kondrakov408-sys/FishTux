package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSanitizeQuery(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"  linux kernel  ", "linux kernel"},
		{"test\x00\x07injection", "testinjection"},
		{"", ""},
	}

	for _, c := range cases {
		got := sanitizeQuery(c.input)
		if got != c.expected {
			t.Errorf("sanitizeQuery(%q) = %q; want %q", c.input, got, c.expected)
		}
	}
}

func TestSearchHandlerEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=", nil)
	w := httptest.NewRecorder()

	searchHandler(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var res SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if len(res.Results) != 0 {
		t.Errorf("expected 0 results for empty query, got %d", len(res.Results))
	}
}

func TestSearchHandlerLiveQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=Linux", nil)
	w := httptest.NewRecorder()

	searchHandler(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var res SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if res.Query != "Linux" {
		t.Errorf("expected query 'Linux', got %q", res.Query)
	}

	if len(res.Results) == 0 {
		t.Logf("Warning: 0 results returned (network might be offline/slow in test)")
	} else {
		t.Logf("Success: returned %d results in %d ms", len(res.Results), res.TookMs)
		for _, item := range res.Results {
			if item.Title == "" || item.URL == "" {
				t.Errorf("result item missing title or url: %+v", item)
			}
		}
	}
}

func TestCORSHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/search", searchHandler)
	handler := corsMiddleware(mux)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/search?q=test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected Access-Control-Allow-Origin: *")
	}
}

func TestInstantAnswers(t *testing.T) {
	// 1. Math calculation
	ans, ok := evaluateMath("25 * 4")
	if !ok || ans != "100" {
		t.Errorf("evaluateMath(25 * 4) = (%q, %v); want (100, true)", ans, ok)
	}

	ansPow, okPow := evaluateMath("2 ^ 8")
	if !okPow || ansPow != "256" {
		t.Errorf("evaluateMath(2 ^ 8) = (%q, %v); want (256, true)", ansPow, okPow)
	}

	// 2. Linux command
	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=tar", nil)
	w := httptest.NewRecorder()
	searchHandler(w, req)

	var res SearchResponse
	if err := json.NewDecoder(w.Result().Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res.InstantAnswer == nil || res.InstantAnswer.Type != "linux_cmd" {
		t.Errorf("expected instant answer for 'tar', got %+v", res.InstantAnswer)
	}
}
