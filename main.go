package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const maxBundleSize = 10 * 1024 * 1024
const maxResponseSize = 6*maxBundleSize + 1024*1024 // JSON can escape each byte.

var validClusterName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "topf-infisical: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 3 || args[0] != "secrets" || (args[1] != "get" && args[1] != "put") {
		return errors.New("usage: topf-infisical secrets <get|put> <cluster-name>")
	}
	name := args[2]
	if !validClusterName.MatchString(name) {
		return errors.New("cluster name must start with a letter or number and contain only letters, numbers, '.', '_' or '-'")
	}
	var bundle []byte
	if args[1] == "put" {
		var err error
		bundle, err = io.ReadAll(io.LimitReader(stdin, maxBundleSize+1))
		if err != nil {
			return fmt.Errorf("read secrets bundle: %w", err)
		}
		if err := validateBundle(string(bundle)); err != nil {
			return err
		}
	}
	c, err := newClient(ctx)
	if err != nil {
		return err
	}
	value, found, err := c.get(ctx, name)
	if err != nil {
		return err
	}
	if args[1] == "get" {
		if !found {
			return nil
		}
		_, err := io.WriteString(stdout, value)
		return err
	}
	method := http.MethodPost
	if found {
		method = http.MethodPatch
	}
	_, err = c.request(ctx, method, "/api/v4/secrets/"+url.PathEscape(name), nil, map[string]any{
		"projectId": c.project, "environment": c.environment, "secretPath": c.path,
		"type": "shared", "secretValue": string(bundle), "skipMultilineEncoding": true,
	})
	return err
}

func validateBundle(bundle string) error {
	if strings.TrimSpace(bundle) == "" {
		return errors.New("refusing an empty secrets bundle")
	}
	if len(bundle) > maxBundleSize {
		return fmt.Errorf("secrets bundle exceeds %d bytes", maxBundleSize)
	}
	if !utf8.ValidString(bundle) {
		return errors.New("secrets bundle is not valid UTF-8")
	}
	return nil
}

type client struct {
	http                                       *http.Client
	baseURL, token, project, environment, path string
}

func newClient(ctx context.Context) (*client, error) {
	c := &client{
		baseURL:     strings.TrimRight(envOrDefault("INFISICAL_API_URL", "https://app.infisical.com"), "/"),
		project:     strings.TrimSpace(os.Getenv("INFISICAL_PROJECT_ID")),
		environment: strings.TrimSpace(os.Getenv("INFISICAL_ENVIRONMENT")),
		path:        envOrDefault("INFISICAL_SECRET_PATH", "/"),
		token:       strings.TrimSpace(os.Getenv("INFISICAL_TOKEN")),
		http: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // Never forward credentials or bundles to another URL.
		}},
	}
	u, err := url.Parse(c.baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("INFISICAL_API_URL must be an HTTP(S) base URL without credentials, query or fragment")
	}
	if c.project == "" || c.environment == "" {
		return nil, errors.New("set INFISICAL_PROJECT_ID and INFISICAL_ENVIRONMENT (environment slug)")
	}
	if !strings.HasPrefix(c.path, "/") {
		return nil, errors.New("INFISICAL_SECRET_PATH must start with '/'")
	}
	// An explicit token is authoritative; never silently fall back after rejection.
	if c.token != "" {
		return c, nil
	}
	id, secret := strings.TrimSpace(os.Getenv("INFISICAL_CLIENT_ID")), strings.TrimSpace(os.Getenv("INFISICAL_CLIENT_SECRET"))
	if id == "" && secret == "" {
		// Let the CLI read its own login/keyring; keep the token only in memory.
		cmd := exec.CommandContext(ctx, "infisical", "user", "get", "token", "--plain", "--silent", "--domain", c.baseURL+"/api")
		output, err := cmd.Output()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("read Infisical CLI login: ensure infisical is installed, run infisical login for INFISICAL_API_URL, and unlock your keyring; alternatively set INFISICAL_TOKEN or INFISICAL_CLIENT_ID + INFISICAL_CLIENT_SECRET")
		}
		c.token = strings.TrimSpace(string(output))
		if c.token == "" || strings.ContainsAny(c.token, " \t\r\n") {
			return nil, errors.New("Infisical CLI returned no valid access token; run infisical login again")
		}
		return c, nil
	}
	if id == "" || secret == "" {
		return nil, errors.New("set INFISICAL_TOKEN (access token) or INFISICAL_CLIENT_ID + INFISICAL_CLIENT_SECRET (Universal Auth)")
	}
	body, err := c.request(ctx, http.MethodPost, "/api/v1/auth/universal-auth/login", nil, map[string]string{"clientId": id, "clientSecret": secret})
	if err != nil {
		return nil, fmt.Errorf("Universal Auth login: %w", err)
	}
	var login struct {
		AccessToken string `json:"accessToken"`
	}
	if json.Unmarshal(body, &login) != nil || strings.TrimSpace(login.AccessToken) == "" {
		return nil, errors.New("Universal Auth login returned no valid access token")
	}
	c.token = login.AccessToken
	return c, nil
}

type apiError struct {
	status  int
	message string // Used only to classify missing secrets, never printed.
}

func (e *apiError) Error() string {
	return fmt.Sprintf("Infisical API returned HTTP %d (%s)", e.status, http.StatusText(e.status))
}

func (c *client) get(ctx context.Context, name string) (string, bool, error) {
	query := url.Values{
		"projectId": {c.project}, "environment": {c.environment}, "secretPath": {c.path},
		"type": {"shared"}, "viewSecretValue": {"true"},
		"expandSecretReferences": {"false"}, "includeImports": {"false"},
	}
	body, err := c.request(ctx, http.MethodGet, "/api/v4/secrets/"+url.PathEscape(name), query, nil)
	if err != nil {
		var apiErr *apiError
		// A generic 404 can mean an incorrect project, environment, folder or URL.
		// Only Infisical's explicit missing-secret response means bootstrap is safe.
		if errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound && apiErr.message == fmt.Sprintf("Secret with name '%s' not found", name) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read secrets: %w", err)
	}
	var result struct {
		Secret *struct {
			Value  *string `json:"secretValue"`
			Hidden bool    `json:"secretValueHidden"`
		} `json:"secret"`
	}
	if json.Unmarshal(body, &result) != nil || result.Secret == nil || result.Secret.Value == nil || result.Secret.Hidden {
		return "", false, errors.New("Infisical returned an invalid or hidden secret value")
	}
	if err := validateBundle(*result.Secret.Value); err != nil {
		return "", false, err
	}
	return *result.Secret.Value, true, nil
}

func (c *client) request(ctx context.Context, method, path string, query url.Values, payload any) ([]byte, error) {
	var reader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, errors.New("encode API request")
		}
		reader = bytes.NewReader(data)
	}
	endpoint := c.baseURL + path
	if len(query) != 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, errors.New("construct API request")
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("Infisical request failed; check connectivity, TLS certificates and API URL")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, errors.New("read Infisical response")
	}
	if len(body) > maxResponseSize {
		return nil, errors.New("Infisical response exceeds size limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var detail struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &detail)
		return nil, &apiError{status: resp.StatusCode, message: detail.Message}
	}
	return body, nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
