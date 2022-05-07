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
	token := New(10*time.Second, "", "", "", []byte(SECRET)) + "1"
	if err := VerifySignature(token, []byte(SECRET)); err == nil {
		t.Error(fmt.Errorf("verification signature error"))
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
