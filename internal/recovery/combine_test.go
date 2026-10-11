package recovery

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/v3/tss"
)

// A 3-of-5 sharing: f(x) = secret + 7x + 11x^2, so any 3+ shares recover the secret and 2 do not.
func TestLagrangeAnyQuorumAboveThreshold(t *testing.T) {
	order := tss.S256().Params().N
	secret := big.NewInt(424242)
	f := func(x int64) *big.Int {
		v := big.NewInt(11 * x * x)
		v.Add(v, big.NewInt(7*x))
		v.Add(v, secret)
		return v.Mod(v, order)
	}
	xs := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)}
	ys := make([]*big.Int, len(xs))
	for i, x := range xs {
		ys[i] = f(x.Int64())
	}

	for n := 3; n <= len(xs); n++ {
		got, err := lagrange(xs[:n], ys[:n], order)
		if err != nil {
			t.Fatal(err)
		}
		if got.Cmp(secret) != 0 {
			t.Errorf("%d shares: got %s, want %s", n, got, secret)
		}
	}
	got, err := lagrange(xs[3:], ys[3:], order)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(secret) == 0 {
		t.Error("2 shares of a 3-of-5 sharing should not recover the secret")
	}
}
