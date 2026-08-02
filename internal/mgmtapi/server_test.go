package mgmtapi

import "testing"

func newTestServer(enroller Enroller) *Server {
	return newTestServerWithClient(enroller, &fakeClientReg{})
}

func newTestServerWithClient(enroller Enroller, clientReg ClientRegistrationStore) *Server {
	if enroller == nil {
		enroller = &fakeEnroller{}
	}
	srv, err := New(enroller, NewInMemoryEnrollmentSessionStore(), clientReg, testRegBaseURL, nil)
	if err != nil {
		panic(err)
	}
	return srv
}

func TestNew_RejectsMissingRequiredCollaborators(t *testing.T) {
	tests := []struct {
		name     string
		enroller Enroller
		sessions EnrollmentSessionStore
		clients  ClientRegistrationStore
		baseURL  string
	}{
		{
			name:     "enroller",
			sessions: NewInMemoryEnrollmentSessionStore(),
			clients:  &fakeClientReg{},
			baseURL:  testRegBaseURL,
		},
		{
			name:     "enrollment session store",
			enroller: &fakeEnroller{},
			clients:  &fakeClientReg{},
			baseURL:  testRegBaseURL,
		},
		{
			name:     "client registration store",
			enroller: &fakeEnroller{},
			sessions: NewInMemoryEnrollmentSessionStore(),
			baseURL:  testRegBaseURL,
		},
		{
			name:     "registration base URL",
			enroller: &fakeEnroller{},
			sessions: NewInMemoryEnrollmentSessionStore(),
			clients:  &fakeClientReg{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.enroller, tt.sessions, tt.clients, tt.baseURL, nil); err == nil {
				t.Fatalf("New accepted a nil %s", tt.name)
			}
		})
	}
}
