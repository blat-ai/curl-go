package curlgo

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransportPreservesExactRequestPathAndQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(w, request.RequestURI)
	}))
	defer server.Close()
	client := transportClient(t)
	for _, target := range []string{
		"/one/../two?value=../kept&repeat=1&repeat=2",
		"/one/./two?fixed=1",
		"/../root?value=./unchanged",
		"//a/./b/../c//?escaped=%2F.%2E%2F&plus=a+b",
		"/a/%2E%2E/b?raw=%2E%2E",
		"/first/../second?fixed=1#excluded-fragment",
	} {
		t.Run(target, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, server.URL+target, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := request.URL.RequestURI()
			response, err := client.Do(request)
			if body := responseBytes(t, response, err); string(body) != want {
				t.Fatalf("native request target=%q, want original %q", body, want)
			}
		})
	}
}
