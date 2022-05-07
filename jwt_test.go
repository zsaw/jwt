package jwt

import (
	"fmt"
	"testing"
	"time"
)

const SECRET = "NTDSCPPSYX"

func TestNew(t *testing.T) {
	token := New(10*time.Second, "", "", "", []byte(SECRET))
	fmt.Println(token)
}

func TestVerifySignature(t *testing.T) {
	tokens := []string{
		"",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIiLCJleHAiOjE2NTE5MzAzMTQsInN1YiI6IiIsImF1ZCI6IiIsIm5iZiI6MTY1MTkzMDMwNCwiaWF0IjoxNjUxOTMwMzA0LCJqdGkiOiI5M2QxNTJjYi0xNmM2LTQzMTEtYjMwZi0wZjlkZTg2NDIwYTYifQ",
		New(10*time.Second, "", "", "", []byte(SECRET)) + "1",
	}

	for i := 0; i < len(tokens); i++ {
		if err := VerifySignature(tokens[i], []byte(SECRET)); err == nil {
			t.Error(fmt.Errorf("verification signature error"))
			break
		}
	}
}

func TestRefresh(t *testing.T) {
	oldToken := New(10*time.Second, "", "", "", []byte(SECRET))
	newToken, err := Refresh(oldToken, 10*time.Second, []byte(SECRET))
	if err != nil {
		t.Error(err)
	}

	if err := VerifySignature(newToken, []byte(SECRET)); err != nil {
		t.Error(err)
	}
}
