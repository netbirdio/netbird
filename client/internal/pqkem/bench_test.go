package pqkem

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
)

func BenchmarkX25519Keygen(b *testing.B) {
	c := ecdh.X25519()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.GenerateKey(rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkX25519ECDH(b *testing.B) {
	c := ecdh.X25519()
	a, _ := c.GenerateKey(rand.Reader)
	p, _ := c.GenerateKey(rand.Reader)
	pub := p.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.ECDH(pub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLKEMKeygen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := mlkem.GenerateKey768(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLKEMEncaps(b *testing.B) {
	dk, _ := mlkem.GenerateKey768()
	ek := dk.EncapsulationKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ek.Encapsulate()
	}
}

func BenchmarkMLKEMDecaps(b *testing.B) {
	dk, _ := mlkem.GenerateKey768()
	_, ct := dk.EncapsulationKey().Encapsulate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dk.Decapsulate(ct); err != nil {
			b.Fatal(err)
		}
	}
}
