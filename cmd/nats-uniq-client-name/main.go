package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"

	"github.com/shvedko/nats-uniq-client-name/internal/uniq"
)

/*
 *	nk -gen account -pubout
 *
 *	accounts {
 *	  SYS {
 *		users: [ { user: admin, password: password } ]
 *	  }
 *	  APP { }
 *	}
 *
 *	system_account: SYS
 *
 *	authorization {
 *	  auth_callout {
 *		issuer: AA3MCC7NAP5TM6TJFOYHSWAKLBNUFM3MTCRV6H6XD2ZNRRZ2KFTUUV6Z
 *		auth_users: [ admin ]
 *		account: SYS
 *	  }
 *	}
 *
 */

const Seed = "SAAGYA5HIPHPB2NZTTZTF5BGX6YNLGLMXIYPUPNJPIN7Z4QQSTCGT3NFRY"

func main() {
	u := uniq.New(
		nats.Options{
			Servers:              []string{"nats:4222"},
			AllowReconnect:       true,
			RetryOnFailedConnect: true,
			UserInfo: func() (string, string) {
				return "admin", "password"
			},
		}, redis.Options{
			Addr:     "redis:6379",
			Protocol: 2,
		})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	err := u.Start(ctx, Seed, map[string]map[string]string{"APP": {"staff": "password"}})
	if err != nil {
		log.Fatalln(err)
	}
}
