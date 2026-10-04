package solana

import (
	"context"
	"fmt"
	"time"
)

// Broadcast sends transactions in order, waiting for each to confirm; a failed wallet stops its own later txs.
func Broadcast(ctx context.Context, c *Client, signed *Signed, logf func(string, ...any)) error {
	failedWallets := map[string]bool{}
	failures := 0
	for i, tx := range signed.Txs {
		if failedWallets[tx.Signer] {
			logf("[%d/%d] skipped (earlier tx of %s failed): %s", i+1, len(signed.Txs), tx.Signer, tx.Description)
			failures++
			continue
		}
		sig, err := c.SendTransaction(ctx, tx.Tx)
		if err == nil {
			err = c.WaitConfirmed(ctx, sig, 60*time.Second)
		}
		if err != nil {
			failedWallets[tx.Signer] = true
			failures++
			logf("[%d/%d] FAILED %s: %v", i+1, len(signed.Txs), tx.Description, err)
			continue
		}
		logf("[%d/%d] confirmed %s  %s", i+1, len(signed.Txs), sig, tx.Description)
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d transactions did not complete", failures, len(signed.Txs))
	}
	return nil
}
