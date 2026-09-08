// Test for issue #270: ClearlyDefined Harvest API now returns 201 Created
// on success, but queueHarvest only accepted exactly 200, so a successful
// harvest request was reported as an error.
package clearlydef

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/guacsec/sw-id-core/coordinates"
	"github.com/hashicorp/go-retryablehttp"
)

type fakeRoundTripper struct {
	status int
}

func (f *fakeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: f.status,
		Status:     http.StatusText(f.status),
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    r,
	}, nil
}

func newFakeStatusClient(status int) *retryablehttp.Client {
	c := retryablehttp.NewClient()
	c.RetryMax = 0
	c.Logger = nil
	c.HTTPClient.Transport = &fakeRoundTripper{status: status}
	return c
}

func testCoordinate() coordinates.Coordinate {
	return coordinates.Coordinate{
		CoordinateType: "npm",
		Provider:       "npmjs",
		Namespace:      "-",
		Name:           "example",
		Revision:       "1.0.0",
	}
}

// Issue #270: the real API now answers 201 Created for a queued harvest.
// queueHarvest must treat this as success, not as an error.
func TestQueueHarvest_Returns201_IsTreatedAsSuccess(t *testing.T) {
	client := newFakeStatusClient(http.StatusCreated) // 201
	err := queueHarvest(context.Background(), client, testCoordinate())
	if err != nil {
		t.Fatalf("expected 201 Created to be treated as success, got error: %v", err)
	}
}

func TestQueueHarvest_Returns200_IsTreatedAsSuccess(t *testing.T) {
	client := newFakeStatusClient(http.StatusOK) // 200, pre-existing behavior
	err := queueHarvest(context.Background(), client, testCoordinate())
	if err != nil {
		t.Fatalf("expected 200 OK to be treated as success, got error: %v", err)
	}
}

// Make sure the fix does not silently swallow genuine failures.
func TestQueueHarvest_Returns500_IsStillAnError(t *testing.T) {
	client := newFakeStatusClient(http.StatusInternalServerError) // 500
	err := queueHarvest(context.Background(), client, testCoordinate())
	if err == nil {
		t.Fatalf("expected HTTP 500 to still be reported as an error")
	}
}
