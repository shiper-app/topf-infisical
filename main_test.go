package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	for key, value := range map[string]string{
		"INFISICAL_API_URL": server.URL, "INFISICAL_PROJECT_ID": "project-id",
		"INFISICAL_ENVIRONMENT": "prod", "INFISICAL_SECRET_PATH": "/topf",
		"INFISICAL_TOKEN": "test-token", "INFISICAL_CLIENT_ID": "", "INFISICAL_CLIENT_SECRET": "",
	} {
		t.Setenv(key, value)
	}
}

func TestRoundTrip(t *testing.T) {
	var stored *string
	var methods []string
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.URL.Path != "/api/v4/secrets/cluster-1" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("incorrect request: %s", r.URL.Path)
		}
		if r.Method == "GET" {
			q := r.URL.Query()
			for key, want := range map[string]string{"projectId": "project-id", "environment": "prod", "secretPath": "/topf", "type": "shared", "viewSecretValue": "true", "includeImports": "false", "expandSecretReferences": "false"} {
				if q.Get(key) != want {
					t.Errorf("query %s = %q", key, q.Get(key))
				}
			}
			if stored == nil {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"message":"Secret with name 'cluster-1' not found"}`)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"secret": map[string]any{"secretValue": *stored}})
			return
		}
		var body struct {
			Project string `json:"projectId"`
			Env     string `json:"environment"`
			Path    string `json:"secretPath"`
			Type    string `json:"type"`
			Value   string `json:"secretValue"`
			Raw     bool   `json:"skipMultilineEncoding"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Project != "project-id" || body.Env != "prod" || body.Path != "/topf" || body.Type != "shared" || !body.Raw {
			t.Errorf("incorrect write scope")
		}
		if stored == nil && r.Method != "POST" || stored != nil && r.Method != "PATCH" {
			t.Errorf("wrong write method: %s", r.Method)
		}
		stored = &body.Value
		fmt.Fprint(w, `{}`)
	})
	ctx := context.Background()
	var out bytes.Buffer
	if err := run(ctx, []string{"secrets", "get", "cluster-1"}, nil, &out); err != nil || out.Len() != 0 {
		t.Fatalf("missing: %v, %q", err, out.String())
	}
	for _, bundle := range []string{"key: |\n  multiline\n  ${untouched}\n", "key: changed\n"} {
		out.Reset()
		if err := run(ctx, []string{"secrets", "put", "cluster-1"}, strings.NewReader(bundle), &out); err != nil {
			t.Fatal(err)
		}
		if out.Len() != 0 {
			t.Fatal("put wrote to stdout")
		}
		if err := run(ctx, []string{"secrets", "get", "cluster-1"}, nil, &out); err != nil {
			t.Fatal(err)
		}
		if out.String() != bundle {
			t.Fatalf("bundle changed: %q", out.String())
		}
	}
	if strings.Join(methods, ",") != "GET,GET,POST,GET,GET,PATCH,GET" {
		t.Fatal(methods)
	}
}

func TestReadFailuresNeverBootstrapOrWrite(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", 401, `{"message":"private-token"}`},
		{"forbidden", 403, `{"message":"private-token"}`},
		{"wrong-folder", 404, `{"message":"Folder not found"}`},
		{"generic-404", 404, `not found`},
		{"server-error", 500, `private-token`},
		{"malformed", 200, `invalid`},
		{"missing-value", 200, `{"secret":{}}`},
		{"null-value", 200, `{"secret":{"secretValue":null}}`},
		{"empty-value", 200, `{"secret":{"secretValue":""}}`},
		{"hidden-value", 200, `{"secret":{"secretValue":"***","secretValueHidden":true}}`},
		{"wrong-type", 200, `{"secret":{"secretValue":123}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setup(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Errorf("unexpected write")
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			for _, action := range []string{"get", "put"} {
				var out bytes.Buffer
				err := run(context.Background(), []string{"secrets", action, "cluster-1"}, strings.NewReader("key: value\n"), &out)
				if err == nil || out.Len() != 0 {
					t.Fatalf("expected failure without output: %v", err)
				}
				if strings.Contains(err.Error(), "private-token") {
					t.Fatal("error leaked response body")
				}
			}
		})
	}
}

func TestAuthentication(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			logins := 0
			setup(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/auth/universal-auth/login" {
					logins++
					var body map[string]string
					json.NewDecoder(r.Body).Decode(&body)
					if r.Method != "POST" || body["clientId"] != "id" || body["clientSecret"] != "secret" || r.Header.Get("Authorization") != "" {
						t.Error("incorrect login")
					}
					fmt.Fprint(w, `{"accessToken":"issued-token"}`)
					return
				}
				want := "Bearer issued-token"
				if explicit {
					want = "Bearer test-token"
				}
				if r.Header.Get("Authorization") != want {
					t.Error("wrong token")
				}
				fmt.Fprint(w, `{"secret":{"secretValue":"key: value\n"}}`)
			})
			t.Setenv("INFISICAL_CLIENT_ID", "id")
			t.Setenv("INFISICAL_CLIENT_SECRET", "secret")
			if !explicit {
				t.Setenv("INFISICAL_TOKEN", "")
			}
			if err := run(context.Background(), []string{"secrets", "get", "cluster-1"}, nil, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			want := 1
			if explicit {
				want = 0
			}
			if logins != want {
				t.Fatalf("logins=%d", logins)
			}
		})
	}
}

func TestCLILogin(t *testing.T) {
	for _, tc := range []struct {
		name, script, id, token string
		wantError               bool
	}{
		{"login", "printf 'cli-token\\n'", "", "", false},
		{"failed", "echo private-credential >&2; exit 1", "", "", true},
		{"empty", "exit 0", "", "", true},
		{"malformed", "printf 'unexpected output\\n'", "", "", true},
		{"partial-universal-auth", "printf 'cli-token'", "partial-id", "", true},
		{"explicit-token", "exit 1", "", "cli-token", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.wantError {
					t.Error("unexpected API request")
				}
				if r.Header.Get("Authorization") != "Bearer cli-token" {
					t.Error("incorrect CLI token")
				}
				fmt.Fprint(w, `{"secret":{"secretValue":"key: value\n"}}`)
			})
			t.Setenv("INFISICAL_TOKEN", tc.token)
			t.Setenv("INFISICAL_CLIENT_ID", tc.id)
			dir := t.TempDir()
			script := "#!/bin/sh\n" + `test "$#" -eq 7 && test "$1" = user && test "$2" = get && test "$3" = token && test "$4" = --plain && test "$5" = --silent && test "$6" = --domain && test "$7" = "$INFISICAL_API_URL/api" || exit 2` + "\n" + tc.script + "\n"
			if err := os.WriteFile(filepath.Join(dir, "infisical"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			var out bytes.Buffer
			err := run(context.Background(), []string{"secrets", "get", "shiper"}, nil, &out)
			if (err != nil) != tc.wantError {
				t.Fatalf("unexpected result: %v", err)
			}
			if err != nil && (strings.Contains(err.Error(), "private-credential") || out.Len() != 0) {
				t.Fatal("failed login leaked output")
			}
			if err == nil && out.String() != "key: value\n" {
				t.Fatal("bundle changed")
			}
		})
	}
}

func TestInvalidInputDoesNotContactAPI(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected API call") })
	for _, args := range [][]string{nil, {"secrets", "delete", "cluster"}, {"nodes", "get", "cluster"}, {"secrets", "get", "../bad"}, {"secrets", "get", ".."}} {
		if run(context.Background(), args, nil, &bytes.Buffer{}) == nil {
			t.Errorf("accepted %v", args)
		}
	}
	for _, bundle := range []string{"", " \n", string([]byte{0xff}), strings.Repeat("x", maxBundleSize+1)} {
		if run(context.Background(), []string{"secrets", "put", "cluster"}, strings.NewReader(bundle), &bytes.Buffer{}) == nil {
			t.Error("accepted invalid bundle")
		}
	}
}

func TestRedirectDoesNotForwardCredentials(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed redirect") }))
	defer target.Close()
	setup(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) })
	if run(context.Background(), []string{"secrets", "get", "cluster"}, nil, &bytes.Buffer{}) == nil {
		t.Fatal("accepted redirect")
	}
}

func TestWriteFailure(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"Secret with name 'cluster' not found"}`)
			return
		}
		w.WriteHeader(403)
		fmt.Fprint(w, `{"message":"secret bundle"}`)
	})
	var out bytes.Buffer
	if err := run(context.Background(), []string{"secrets", "put", "cluster"}, strings.NewReader("key: value"), &out); err == nil || out.Len() != 0 {
		t.Fatalf("write failure: %v", err)
	}
}
