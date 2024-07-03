package redigo_driver

import (
	redigo "github.com/gomodule/redigo/redis"
	"github.com/jonkwee/go-guerrilla/backends"
)

func init() {
	backends.RedisDialer = func(network, address string, options ...backends.RedisDialOption) (backends.RedisConn, error) {
		return redigo.Dial(network, address)
	}
}
