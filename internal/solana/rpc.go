package solana

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

var errRateLimited = errors.New("RPC rate limit exceeded, use your own RPC URL")

type Client struct {
	URL  string
	HTTP *http.Client
}

func NewClient(url string) *Client {
	return &Client{URL: url, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

const maxRateLimitRetries = 6

func (c *Client) call(ctx context.Context, method string, params []any, out any) error {
	backoff := time.Second
	for attempt := 0; ; attempt++ {
		err := c.callOnce(ctx, method, params, out)
		if err == nil || !errors.Is(err, errRateLimited) || attempt >= maxRateLimitRetries {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

func (c *Client) callOnce(ctx context.Context, method string, params []any, out any) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("%s: %w", method, errRateLimited)
	}
	var decoded rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return fmt.Errorf("%s: decode response (HTTP %d): %w", method, resp.StatusCode, err)
	}
	if decoded.Error != nil {
		if decoded.Error.Code == http.StatusTooManyRequests {
			return fmt.Errorf("%s: %w", method, errRateLimited)
		}
		return fmt.Errorf("%s: %s", method, decoded.Error.Message)
	}
	return json.Unmarshal(decoded.Result, out)
}

func (c *Client) GetBalance(ctx context.Context, address string) (uint64, error) {
	var res struct {
		Value uint64 `json:"value"`
	}
	err := c.call(ctx, "getBalance", []any{address, map[string]string{"commitment": "confirmed"}}, &res)
	return res.Value, err
}

func (c *Client) GetLatestBlockhash(ctx context.Context) (string, uint64, error) {
	var res struct {
		Value struct {
			Blockhash            string `json:"blockhash"`
			LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
		} `json:"value"`
	}
	err := c.call(ctx, "getLatestBlockhash", []any{map[string]string{"commitment": "confirmed"}}, &res)
	return res.Value.Blockhash, res.Value.LastValidBlockHeight, err
}

func (c *Client) GetRentExemption(ctx context.Context, space uint64) (uint64, error) {
	var res uint64
	err := c.call(ctx, "getMinimumBalanceForRentExemption", []any{space}, &res)
	return res, err
}

func (c *Client) AccountExists(ctx context.Context, address string) (bool, error) {
	var res struct {
		Value *json.RawMessage `json:"value"`
	}
	err := c.call(ctx, "getAccountInfo", []any{address, map[string]string{"encoding": "base64", "commitment": "confirmed"}}, &res)
	return res.Value != nil && string(*res.Value) != "null", err
}

type TokenAccount struct {
	Address  string
	Program  PublicKey
	Mint     string
	Amount   uint64
	Decimals uint8
	Lamports uint64
	Frozen   bool
}

func (c *Client) GetTokenAccounts(ctx context.Context, owner string, program PublicKey) ([]TokenAccount, error) {
	var res struct {
		Value []struct {
			Pubkey  string `json:"pubkey"`
			Account struct {
				Lamports uint64 `json:"lamports"`
				Data     struct {
					Parsed struct {
						Info struct {
							Mint        string `json:"mint"`
							State       string `json:"state"`
							TokenAmount struct {
								Amount   string `json:"amount"`
								Decimals uint8  `json:"decimals"`
							} `json:"tokenAmount"`
						} `json:"info"`
					} `json:"parsed"`
				} `json:"data"`
			} `json:"account"`
		} `json:"value"`
	}
	params := []any{owner, map[string]string{"programId": program.String()}, map[string]string{"encoding": "jsonParsed", "commitment": "confirmed"}}
	if err := c.call(ctx, "getTokenAccountsByOwner", params, &res); err != nil {
		return nil, err
	}
	out := make([]TokenAccount, 0, len(res.Value))
	for _, v := range res.Value {
		info := v.Account.Data.Parsed.Info
		amount, err := strconv.ParseUint(info.TokenAmount.Amount, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("token account %s: bad amount %q", v.Pubkey, info.TokenAmount.Amount)
		}
		out = append(out, TokenAccount{
			Address: v.Pubkey, Program: program, Mint: info.Mint, Amount: amount,
			Decimals: info.TokenAmount.Decimals, Lamports: v.Account.Lamports, Frozen: info.State == "frozen",
		})
	}
	return out, nil
}

func (c *Client) SendTransaction(ctx context.Context, txBase64 string) (string, error) {
	var sig string
	err := c.call(ctx, "sendTransaction", []any{txBase64, map[string]any{"encoding": "base64", "preflightCommitment": "confirmed"}}, &sig)
	return sig, err
}

// WaitConfirmed polls until the signature is confirmed, failed, or the timeout passes.
func (c *Client) WaitConfirmed(ctx context.Context, signature string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var res struct {
			Value []*struct {
				Err                any    `json:"err"`
				ConfirmationStatus string `json:"confirmationStatus"`
			} `json:"value"`
		}
		if err := c.call(ctx, "getSignatureStatuses", []any{[]string{signature}}, &res); err != nil {
			return err
		}
		if len(res.Value) == 1 && res.Value[0] != nil {
			st := res.Value[0]
			if st.Err != nil {
				return fmt.Errorf("transaction failed on-chain: %v", st.Err)
			}
			if st.ConfirmationStatus == "confirmed" || st.ConfirmationStatus == "finalized" {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("timed out waiting for %s", signature)
}
