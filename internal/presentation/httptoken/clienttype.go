package httptoken

import (
	"errors"
	"net/http"
)

type ClientType string

const (
	ClientWeb    ClientType = "web"
	ClientMobile ClientType = "mobile"
)

func FromRequest(request *http.Request) (ClientType, error) {
	clientType := request.Header.Get("Authorization")
	switch clientType {
	case "web":
		return ClientWeb, nil
	case "mobile":
		return ClientMobile, nil
	default:
		return "", errors.New("unsupported client type")
	}
}
