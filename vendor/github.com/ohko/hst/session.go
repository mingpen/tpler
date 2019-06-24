package hst

import (
	"time"
)

// const
const (
	SESSIONKEY = "HST_SESSION"
)

type memSessionData struct {
	Data   interface{}
	Expire time.Time
}

// Session ...
type Session interface {
	Set(c *Context, domain, path, key string, value interface{}, expire time.Duration) error
	Get(c *Context, key string) (interface{}, error)
	Destory(c *Context) error
}
