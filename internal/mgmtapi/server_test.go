package mgmtapi

import "testing"

func TestNew_RejectsMissingRequiredCollaborators(t *testing.T) {
	tests := []struct {
		name     string
		enroller Enroller
		sessions EnrollmentSessionStore
		clients  ClientRegistrationStore
	}{
		{
			name:     "enroller",
			sessions: NewInMemoryEnrollmentSessionStore(),
			clients:  &fakeClientReg{},
		},
		{
			name:     "enrollment session store",
			enroller: &fakeEnroller{},
			clients:  &fakeClientReg{},
		},
		{
			name:     "client registration store",
			enroller: &fakeEnroller{},
			sessions: NewInMemoryEnrollmentSessionStore(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.enroller, tt.sessions, tt.clients, testRegBaseURL, nil); err == nil {
				t.Fatalf("New accepted a nil %s", tt.name)
			}
		})
	}
}
