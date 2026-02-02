package uniq

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/redis/go-redis/v9"
)

type Uniq struct {
	options1 nats.Options
	options2 redis.Options
	done     chan error
}

func (u *Uniq) Stop() {
	close(u.done)
}

func (u *Uniq) Start(ctx context.Context, seed string, accounts map[string]map[string]string) error {
	keys, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return err
	}

	conn2 := DB{Client: redis.NewClient(&u.options2)}

	defer conn2.Close()

	err = conn2.Ping(ctx).Err()
	if err != nil {
		return err
	}

	conn1, err := u.options1.Connect()
	if err != nil {
		return err
	}

	defer conn1.Close()

	auth, err := conn1.QueueSubscribe("$SYS.REQ.USER.AUTH", "UNIQUER", func(msg *nats.Msg) {
		err := conn2.Authentication(ctx, keys, accounts, msg)
		if err != nil {
			log.Println("Authentication:", err)
		}
	})
	if err != nil {
		return err
	}

	defer auth.Unsubscribe()

	disc, err := conn1.QueueSubscribe("$SYS.ACCOUNT.*.DISCONNECT", "UNIQUER", func(msg *nats.Msg) {
		err := conn2.Disconnection(ctx, accounts, msg)
		if err != nil {
			log.Println("Disconnection:", err)
		}
	})
	if err != nil {
		return err
	}

	defer disc.Unsubscribe()

	return <-u.done
}

type DB struct {
	*redis.Client
}

func (db DB) Authentication(ctx context.Context, keys nkeys.KeyPair, accounts map[string]map[string]string, msg *nats.Msg) error {
	req, err := jwt.DecodeAuthorizationRequestClaims(bytes.NewBuffer(msg.Data).String())
	if err != nil {
		return fmt.Errorf("error decode authorization request: %w", err)
	}

	if !strings.HasPrefix(req.Issuer, "N") {
		return fmt.Errorf("bad request: expected server: %q", req.Issuer)
	}
	if req.Issuer != req.Server.ID {
		return fmt.Errorf("bad request: issuers don't match: %q != %q", req.Issuer, req.Server.ID)
	}
	if req.Audience != "nats-authorization-request" {
		return fmt.Errorf("bad request: unexpected audience: %q", req.Audience)
	}

	log.Println(req)

	res := jwt.NewAuthorizationResponseClaims(req.UserNkey)
	res.Audience = req.Server.ID

	claims := jwt.NewUserClaims(req.UserNkey)
	claims.Audience = "$G"

	var account, password string
	var ok bool
	var users map[string]string
	for account, users = range accounts {
		password, ok = users[req.ConnectOptions.Username]
		if ok {
			break
		}
	}

	switch {
	case req.ConnectOptions.Username != "" && !ok || password != req.ConnectOptions.Password:
		res.Error = "Authentication Failed"

	case req.ConnectOptions.Username != "":
		key := fmt.Sprintf("UNIQUER/%s", base64.StdEncoding.EncodeToString([]byte(req.ClientInformation.Name)))

		ok, err := db.SetNX(ctx, key, req.ClientInformation.ID, 0).Result()
		if err != nil {
			return fmt.Errorf("set %q failed: %w", key, err)
		}
		if !ok {
			res.Error = "Unique Client Name Required"
			break
		}

		claims.Audience = account
		fallthrough

	default:
		token, err := claims.Encode(keys)
		if err != nil {
			return fmt.Errorf("error encode token: %w", err)
		}
		res.Jwt = token
	}

	data, err := res.Encode(keys)
	if err != nil {
		return fmt.Errorf("error encode response: %w", err)
	}

	return msg.Respond([]byte(data))
}

type Disconnect struct {
	Type      string    `json:"type"`
	Id        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Server    struct {
		Name      string    `json:"name"`
		Host      string    `json:"host"`
		Id        string    `json:"id"`
		Ver       string    `json:"ver"`
		JetStream bool      `json:"jetstream"`
		Flags     int       `json:"flags"`
		Seq       int       `json:"seq"`
		Time      time.Time `json:"time"`
	} `json:"server"`
	Client struct {
		Start      time.Time `json:"start"`
		Host       string    `json:"host"`
		Id         int       `json:"id"`
		Account    string    `json:"acc"`
		Name       string    `json:"name"`
		Lang       string    `json:"lang"`
		Ver        string    `json:"ver"`
		Rtt        int       `json:"rtt"`
		Stop       time.Time `json:"stop"`
		IssuerKey  string    `json:"issuer_key"`
		Kind       string    `json:"kind"`
		ClientType string    `json:"client_type"`
	} `json:"client"`
	Sent struct {
		Messages int `json:"msgs"`
		Bytes    int `json:"bytes"`
	} `json:"sent"`
	Received struct {
		Messages int `json:"msgs"`
		Bytes    int `json:"bytes"`
	} `json:"received"`
	Reason string `json:"reason"`
}

func (db DB) Disconnection(ctx context.Context, accounts map[string]map[string]string, msg *nats.Msg) error {
	var req Disconnect
	err := json.Unmarshal(msg.Data, &req)
	if err != nil {
		return err
	}

	_, ok := accounts[req.Client.Account]
	if !ok {
		return nil
	}

	log.Println(req)

	key := fmt.Sprintf("UNIQUER/%s", base64.StdEncoding.EncodeToString([]byte(req.Client.Name)))

	id, err := db.Get(ctx, key).Int()
	if err != nil {
		return fmt.Errorf("get %q failed: %w", key, err)
	}
	if id != req.Client.Id {
		return fmt.Errorf("mismatch id %d != %d for %q", id, req.Client.Id, key)
	}

	err = db.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("get %q failed: %w", key, err)
	}

	return nil
}

func New(options1 nats.Options, options2 redis.Options) *Uniq {
	options1.AllowReconnect = true

	if options1.MaxReconnect == 0 {
		options1.MaxReconnect = nats.DefaultMaxReconnect
	}
	if options1.ReconnectWait == 0 {
		options1.ReconnectWait = nats.DefaultReconnectWait
	}
	if options1.ReconnectJitter == 0 {
		options1.ReconnectJitter = nats.DefaultReconnectJitter
	}
	if options1.ReconnectJitterTLS == 0 {
		options1.ReconnectJitterTLS = nats.DefaultReconnectJitterTLS
	}
	if options1.Timeout == 0 {
		options1.Timeout = nats.DefaultTimeout
	}
	if options1.PingInterval == 0 {
		options1.PingInterval = nats.DefaultPingInterval
	}
	if options1.MaxPingsOut == 0 {
		options1.MaxPingsOut = nats.DefaultMaxPingOut
	}
	if options1.SubChanLen == 0 {
		options1.SubChanLen = nats.DefaultMaxChanLen
	}
	if options1.ReconnectBufSize == 0 {
		options1.ReconnectBufSize = nats.DefaultReconnectBufSize
	}
	if options1.DrainTimeout == 0 {
		options1.DrainTimeout = nats.DefaultDrainTimeout
	}
	if options1.FlusherTimeout == 0 {
		options1.FlusherTimeout = nats.DefaultFlusherTimeout
	}

	options1.Name = "UNIQUER"

	return &Uniq{
		options1: options1,
		options2: options2,
		done:     make(chan error),
	}
}
