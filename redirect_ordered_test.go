package curlgo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestOrderedHeadersRespectCrossHostRedirectFiltering(t *testing.T) {
	for _, readd := range []bool{false, true} {
		name := "strip-sensitive"
		if readd {
			name = "callback-readds-sensitive"
		}
		t.Run(name, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				_ = json.NewEncoder(w).Encode(request.Header)
			}))
			defer target.Close()
			initialHeaders := make(chan http.Header, 1)
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				initialHeaders <- request.Header.Clone()
				http.Redirect(w, request, strings.Replace(target.URL, "127.0.0.1", "localhost", 1), http.StatusFound)
			}))
			defer source.Close()
			client := transportClient(t)
			client.CheckRedirect = func(request *http.Request, _ []*http.Request) error {
				if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
					t.Errorf("net/http retained sensitive headers on cross-host redirect: %v", request.Header)
				}
				if readd {
					request.Header.Set("Authorization", "Bearer callback")
					request.Header.Set("Cookie", "callback=allowed")
				}
				return nil
			}
			request, err := http.NewRequest(http.MethodGet, source.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			request = WithOrderedHeaders(request, []Header{
				{Name: "Authorization", Value: "Bearer original"},
				{Name: "Cookie", Value: "private=original"},
				{Name: "X-Ordinary", Value: "preserved"},
			})
			data := doBytes(t, client, request)
			sourceHeaders := <-initialHeaders
			var got http.Header
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if sourceHeaders.Get("Authorization") != "Bearer original" || sourceHeaders.Get("Cookie") != "private=original" {
				t.Fatalf("initial ordered credentials were not sent: %v", sourceHeaders)
			}
			wantAuth, wantCookie := "", ""
			if readd {
				wantAuth, wantCookie = "Bearer callback", "callback=allowed"
			}
			if got.Get("Authorization") != wantAuth || got.Get("Cookie") != wantCookie {
				t.Fatalf("redirect sent Authorization=%q Cookie=%q; want %q %q", got.Get("Authorization"), got.Get("Cookie"), wantAuth, wantCookie)
			}
			if got.Get("X-Ordinary") != "preserved" {
				t.Fatalf("ordinary ordered header was lost: %v", got)
			}
		})
	}
}

func TestOrderedHeadersRespectSameHostRedirectEditsAndJar(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "fresh", Path: "/"})
			http.Redirect(w, request, "/target", http.StatusFound)
			return
		}
		_ = json.NewEncoder(w).Encode(request.Header)
	}))
	defer server.Close()
	client := transportClient(t)
	client.CheckRedirect = func(request *http.Request, _ []*http.Request) error {
		request.Header.Set("X-Ordinary", "updated")
		request.Header["X-Duplicate"] = []string{"updated-first", "updated-second"}
		request.Header.Del("X-Deleted")
		return nil
	}
	request, err := http.NewRequest(http.MethodGet, server.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	request = WithOrderedHeaders(request, []Header{
		{Name: "Authorization", Value: "Bearer preserved"},
		{Name: "Cookie", Value: "session=stale; untouched=yes"},
		{Name: "X-Duplicate", Value: "original-first"},
		{Name: "X-Ordinary", Value: "original"},
		{Name: "X-Duplicate", Value: "original-second"},
		{Name: "X-Deleted", Value: "must-disappear"},
	})
	data := doBytes(t, client, request)
	var got http.Header
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Get("Authorization") != "Bearer preserved" {
		t.Fatalf("same-host redirect lost authorization: %v", got)
	}
	if got.Get("X-Ordinary") != "updated" || got.Get("X-Deleted") != "" || !reflect.DeepEqual(got.Values("X-Duplicate"), []string{"updated-first", "updated-second"}) {
		t.Fatalf("redirect callback edits were ignored: %v", got)
	}
	cookies := (&http.Request{Header: got}).Cookies()
	values := make(map[string]string)
	for _, cookie := range cookies {
		if _, duplicate := values[cookie.Name]; duplicate {
			t.Fatalf("redirect duplicated cookie %q: %v", cookie.Name, cookies)
		}
		values[cookie.Name] = cookie.Value
	}
	if !reflect.DeepEqual(values, map[string]string{"session": "fresh", "untouched": "yes"}) {
		t.Fatalf("ordered cookie context overrode jar update: %v", values)
	}
}

func TestWithOrderedHeadersClonesValuesAndUsesCurrentHeaderMap(t *testing.T) {
	original, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	original.Header["X-Duplicate"] = []string{"original"}
	original.Header.Set("X-Z", "sorted")
	fields := []Header{
		{Name: "x-duplicate", Value: "first"},
		{Name: "X-Middle", Value: "middle"},
		{Name: "X-Duplicate", Value: "second"},
		{Name: "X-Empty", Value: ""},
	}
	request := WithOrderedHeaders(original, fields)
	fields[0] = Header{Name: "Authorization", Value: "must-not-appear"}
	if !reflect.DeepEqual(original.Header.Values("X-Duplicate"), []string{"original"}) || original.Header.Get("X-Middle") != "" {
		t.Fatalf("WithOrderedHeaders mutated original request: %v", original.Header)
	}
	request.Header["X-Duplicate"][0] = "changed"
	request.Header.Set("X-Middle", "updated")
	request.Header.Del("X-Z")
	want := []string{"x-duplicate: changed", "X-Middle: updated", "X-Duplicate: second", "X-Empty;", "Expect:", "Content-Type:"}
	if got := requestHeaders(request); !reflect.DeepEqual(got, want) {
		t.Fatalf("current header values/order = %v, want %v", got, want)
	}
	if value, ok := requestHeaderValue(request, "X-Middle"); !ok || value != "updated" {
		t.Fatalf("requestHeaderValue returned stale ordered value: %q, %t", value, ok)
	}
	if original.Header.Get("X-Duplicate") != "original" || original.Header.Get("X-Z") != "sorted" {
		t.Fatalf("cloned header slices still share original storage: %v", original.Header)
	}
	request.Header["Accept"] = nil
	if !slices.Contains(requestHeaders(request), "Accept:") {
		t.Fatal("nil header slice must suppress native browser default")
	}
}
