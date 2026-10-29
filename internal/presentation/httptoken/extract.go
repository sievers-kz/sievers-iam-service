package httptoken

import (
	"errors"
	"net/http"
	"strings"
)

func Extract(request *http.Request) (string, error) {
	clientType, err := FromRequest(request)
	if err != nil {
		return "", err
	}

	switch clientType {
	case ClientWeb:
		cookieToken, err := request.Cookie(accessToken)
		if err != nil || cookieToken.Value == "" {
			return "", errors.New("cookie token not found")
		}
		return cookieToken.Value, nil
	case ClientMobile:
		bearerToken := request.Header.Get("Authorization")
		removePrefix, found := strings.CutPrefix(bearerToken, "Bearer ")
		if !found {
			return "", errors.New("bearer token not found or invalid")
		}

		cleanedToken := strings.TrimSpace(removePrefix)
		if cleanedToken == "" {
			return "", errors.New("bearer token not found or invalid")
		}
		return cleanedToken, nil
	}

	return "", errors.New("an error occurred")
}
