package image

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func TestAnnotateRegistryError(t *testing.T) {
	ref := mustRef(t, "registry.example.com/team/app:1.0")
	tests := []struct {
		name string
		err  error
		want string // substring; "" means the error must come back unchanged
	}{
		{name: "unauthorized status", err: &transport.Error{StatusCode: http.StatusUnauthorized}, want: "registry registry.example.com requires authentication for team/app"},
		{name: "unauthorized code", err: &transport.Error{Errors: []transport.Diagnostic{{Code: transport.UnauthorizedErrorCode}}}, want: "docker login registry.example.com"},
		{name: "forbidden status", err: &transport.Error{StatusCode: http.StatusForbidden}, want: "denied access to team/app"},
		{name: "denied code", err: &transport.Error{Errors: []transport.Diagnostic{{Code: transport.DeniedErrorCode}}}, want: "denied access"},
		{name: "not found status", err: &transport.Error{StatusCode: http.StatusNotFound}, want: "image registry.example.com/team/app:1.0 not found"},
		{name: "manifest unknown code", err: &transport.Error{Errors: []transport.Diagnostic{{Code: transport.ManifestUnknownErrorCode}}}, want: "not found in registry registry.example.com"},
		{name: "name unknown code", err: &transport.Error{Errors: []transport.Diagnostic{{Code: transport.NameUnknownErrorCode}}}, want: "not found"},
		{name: "rate limited", err: &transport.Error{StatusCode: http.StatusTooManyRequests}, want: "rate limiting"},
		{name: "wrapped", err: fmt.Errorf("outer: %w", &transport.Error{StatusCode: http.StatusUnauthorized}), want: "requires authentication"},
		{name: "server error passes through", err: &transport.Error{StatusCode: http.StatusInternalServerError}},
		{name: "plain error passes through", err: errors.New("boom")},
		{name: "nil", err: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := annotateRegistryError(ref, tc.err)
			if tc.want == "" {
				if got != tc.err {
					t.Fatalf("annotateRegistryError changed the error: %v", got)
				}
				return
			}
			if got == nil || !strings.Contains(got.Error(), tc.want) {
				t.Fatalf("annotateRegistryError = %v, want it to contain %q", got, tc.want)
			}
			if !errors.Is(got, tc.err) {
				t.Errorf("original error is not in the chain of %v", got)
			}
		})
	}
}
