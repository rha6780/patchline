// Package slack posts one Slack message per finding with a bot token, keeps
// it current with chat.update and records history in its thread.
//
// The bot needs the chat:write scope (and chat:write.public to post in
// channels it has not joined).
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/notify"
)

// DefaultBaseURL is the Slack Web API.
const DefaultBaseURL = "https://slack.com/api"

// Sink talks to the Slack Web API.
type Sink struct {
	token   string
	baseURL string
	http    *http.Client
}

// New returns a Slack sink. baseURL may be empty (DefaultBaseURL).
func New(token, baseURL string, httpClient *http.Client) *Sink {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Sink{token: token, baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

func (s *Sink) Name() string       { return "slack" }
func (s *Sink) NeedsChannel() bool { return true }

// Post sends a new message.
func (s *Sink) Post(ctx context.Context, channel string, m notify.Message) (notify.Ref, error) {
	resp, err := s.call(ctx, "chat.postMessage", map[string]any{
		"channel":      channel,
		"text":         notify.Summary(m),
		"blocks":       Blocks(m),
		"unfurl_links": false,
		"unfurl_media": false,
	})
	if err != nil {
		return notify.Ref{}, err
	}
	// chat.update needs the channel id, which Slack returns even when the
	// message was posted to "#name".
	return notify.Ref{Channel: resp.Channel, ID: resp.TS}, nil
}

// Update replaces the message.
func (s *Sink) Update(ctx context.Context, ref notify.Ref, m notify.Message) error {
	_, err := s.call(ctx, "chat.update", map[string]any{
		"channel": ref.Channel,
		"ts":      ref.ID,
		"text":    notify.Summary(m),
		"blocks":  Blocks(m),
	})
	return err
}

// Reply posts to the message's thread.
func (s *Sink) Reply(ctx context.Context, ref notify.Ref, text string) error {
	_, err := s.call(ctx, "chat.postMessage", map[string]any{
		"channel":   ref.Channel,
		"thread_ts": ref.ID,
		"text":      text,
	})
	return err
}

type apiResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Channel string `json:"channel"`
	TS      string `json:"ts"`
}

func (s *Sink) call(ctx context.Context, method string, payload map[string]any) (apiResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return apiResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/"+method, bytes.NewReader(body))
	if err != nil {
		return apiResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	res, err := s.http.Do(req)
	if err != nil {
		return apiResponse{}, fmt.Errorf("slack %s: %w", method, err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusTooManyRequests {
		retry := 30 * time.Second
		if v, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && v > 0 {
			retry = time.Duration(v) * time.Second
		}
		return apiResponse{}, &notify.RateLimitError{RetryAfter: retry}
	}
	if res.StatusCode != http.StatusOK {
		return apiResponse{}, fmt.Errorf("slack %s: HTTP %s", method, res.Status)
	}

	var out apiResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return apiResponse{}, fmt.Errorf("slack %s: decode response: %w", method, err)
	}
	if !out.OK {
		if out.Error == "ratelimited" {
			return apiResponse{}, &notify.RateLimitError{RetryAfter: 30 * time.Second}
		}
		return apiResponse{}, fmt.Errorf("slack %s: %s", method, out.Error)
	}
	return out, nil
}
