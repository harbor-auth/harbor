package mgmtapi

import "context"

// fakeCallerSource is a test-only CallerSource that returns a fixed user ID.
// Use it in unit tests to seed the caller identity without the BFF session
// middleware:
//
//	srv.WithCallerSource(fakeCallerSource{userID: "user-123"})
//
// An empty userID simulates an unauthenticated request (callerID will write
// 401 and return ok=false).
type fakeCallerSource struct {
	userID string
}

func (f fakeCallerSource) CallerID(_ context.Context) string {
	return f.userID
}
