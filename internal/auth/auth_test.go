package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		expected  string
		expectErr error
	}{
		{
			name:      "No authorization header",
			headers:   http.Header{},
			expected:  "",
			expectErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "Malformed authorization header",
			headers:   http.Header{"Authorization": {"Bearer token"}},
			expected:  "",
			expectErr: errors.New("malformed authorization header"),
		},
		{
			name:      "Valid API Key header",
			headers:   http.Header{"Authorization": {"ApiKey my-secret-key"}},
			expected:  "my-secret-key",
			expectErr: nil,
		},
		{
			name:      "Authorization header with wrong prefix",
			headers:   http.Header{"Authorization": {"Bearer my-secret-key"}},
			expected:  "",
			expectErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetAPIKey(tt.headers)

			if result != tt.expected {
				t.Errorf("GetAPIKey() got = %v, want %v", result, tt.expected)
			}

			if err != nil && tt.expectErr == nil {
				t.Errorf("GetAPIKey() error = %v, want no error", err)
			}

			if err == nil && tt.expectErr != nil {
				t.Errorf("GetAPIKey() error = nil, want %v", tt.expectErr)
			}

			if err != nil && tt.expectErr != nil && err.Error() != tt.expectErr.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectErr)
			}
		})
	}
}
