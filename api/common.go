package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/gin-gonic/gin"
	"github.com/xqdoo00o/OpenAIAuth/auth"
// 	"github.com/xqdoo00o/funcaptcha"
    http2 "net/http"
    "io/ioutil"
	"github.com/linweiyuan/go-logger/logger"
)

const (
	ChatGPTApiPrefix    = "/chatgpt"
	ImitateApiPrefix    = "/imitate/v1"
	ChatGPTApiUrlPrefix = "https://chat.openai.com"

	PlatformApiPrefix    = "/platform"
	PlatformApiUrlPrefix = "https://api.openai.com"

	defaultErrorMessageKey             = "errorMessage"
	AuthorizationHeader                = "Authorization"
	XAuthorizationHeader               = "X-Authorization"
	ContentType                        = "application/x-www-form-urlencoded"
	UserAgent                          = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
	Auth0Url                           = "https://auth0.openai.com"
	LoginUsernameUrl                   = Auth0Url + "/u/login/identifier?state="
	LoginPasswordUrl                   = Auth0Url + "/u/login/password?state="
	ParseUserInfoErrorMessage          = "failed to parse user login info"
	GetAuthorizedUrlErrorMessage       = "failed to get authorized url"
	EmailInvalidErrorMessage           = "email is not valid"
	EmailOrPasswordInvalidErrorMessage = "email or password is not correct"
	GetAccessTokenErrorMessage         = "failed to get access token"
	defaultTimeoutSeconds              = 600 // 10 minutes

	EmailKey                       = "email"
	AccountDeactivatedErrorMessage = "account %s is deactivated"

	ReadyHint = "service go-chatgpt-api is ready"

	refreshPuidErrorMessage = "failed to refresh PUID"
)

var (
	Client       tls_client.HttpClient
	ArkoseClient tls_client.HttpClient
	PUID         string
	ProxyUrl     string
)

type LoginInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthLogin interface {
	GetAuthorizedUrl(csrfToken string) (string, int, error)
	GetState(authorizedUrl string) (string, int, error)
	CheckUsername(state string, username string) (int, error)
	CheckPassword(state string, username string, password string) (string, int, error)
	GetAccessToken(code string) (string, int, error)
	GetAccessTokenFromHeader(c *gin.Context) (string, int, error)
}

func init() {
	Client, _ = tls_client.NewHttpClient(tls_client.NewNoopLogger(), []tls_client.HttpClientOption{
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithTimeoutSeconds(defaultTimeoutSeconds),
		tls_client.WithClientProfile(profiles.Okhttp4Android13),
	}...)
	ArkoseClient = getHttpClient()

	setupPUID()
}

func NewHttpClient() tls_client.HttpClient {
	client := getHttpClient()

	ProxyUrl = os.Getenv("PROXY")
	if ProxyUrl != "" {
		client.SetProxy(ProxyUrl)
	}

	return client
}

func getHttpClient() tls_client.HttpClient {
	client, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), []tls_client.HttpClientOption{
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithClientProfile(profiles.Okhttp4Android13),
	}...)
	return client
}

func Proxy(c *gin.Context) {
	url := c.Request.URL.Path
	if strings.Contains(url, ChatGPTApiPrefix) {
		url = strings.ReplaceAll(url, ChatGPTApiPrefix, ChatGPTApiUrlPrefix)
	} else if strings.Contains(url, ImitateApiPrefix) {
		url = strings.ReplaceAll(url, ImitateApiPrefix, ChatGPTApiUrlPrefix+"/backend-api")
	} else {
		url = strings.ReplaceAll(url, PlatformApiPrefix, PlatformApiUrlPrefix)
	}

	method := c.Request.Method
	queryParams := c.Request.URL.Query().Encode()
	if queryParams != "" {
		url += "?" + queryParams
	}

	// if not set, will return 404
	c.Status(http.StatusOK)

	var req *http.Request
	if method == http.MethodGet {
		req, _ = http.NewRequest(http.MethodGet, url, nil)
	} else {
		body, _ := io.ReadAll(c.Request.Body)
		req, _ = http.NewRequest(method, url, bytes.NewReader(body))
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set(AuthorizationHeader, GetAccessToken(c))
	resp, err := Client.Do(req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, ReturnMessage(err.Error()))
		return
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			logger.Error(fmt.Sprintf(AccountDeactivatedErrorMessage, c.GetString(EmailKey)))
		}

		responseMap := make(map[string]interface{})
		json.NewDecoder(resp.Body).Decode(&responseMap)
		c.AbortWithStatusJSON(resp.StatusCode, responseMap)
		return
	}

	io.Copy(c.Writer, resp.Body)
}

func ReturnMessage(msg string) gin.H {
	logger.Warn(msg)
    fmt.Printf("test ReturnMessage")
//  测试错误信息输出
    reader := strings.NewReader(msg)
    responseMap := make(map[string]interface{})
    json.NewDecoder(reader).Decode(&responseMap)
    for key, value := range responseMap {
        fmt.Printf("Key: %s, Value: %v\n", key, value)
    }

	return gin.H{
		defaultErrorMessageKey: msg,
	}
}

func GetAccessToken(c *gin.Context) string {
	accessToken := c.GetString(AuthorizationHeader)
	if !strings.HasPrefix(accessToken, "Bearer") {
		return "Bearer " + accessToken
	}

	return accessToken
}

type ArkoseResponse struct {
    Code    int    `json:"code"`
    Token   string `json:"token"`
    Msg     string `json:"msg"`
    Created int    `json:"created"`
}

func GetArkoseToken() (string, error) {
    ProxyUrl = os.Getenv("ARKOSE_TOKEN_URL")
    resp, err := http2.Get(ProxyUrl)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    // Membaca respon HTTP
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }

    // Memeriksa kode status HTTP
    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("Gagal mengambil token. Kode status: %d", resp.StatusCode)
    }
    var response ArkoseResponse

    if err := json.Unmarshal(body, &response); err != nil {
        return "", err
    }

    // Mengembalikan nilai token
    return response.Token, nil
}

func setupPUID() {
	username := os.Getenv("OPENAI_EMAIL")
	password := os.Getenv("OPENAI_PASSWORD")
	if username != "" && password != "" {
		go func() {
			for {
				authenticator := auth.NewAuthenticator(username, password, ProxyUrl)
				if err := authenticator.Begin(); err != nil {
					logger.Warn(fmt.Sprintf("%s: %s", refreshPuidErrorMessage, err.Details))
					return
				}

				accessToken := authenticator.GetAccessToken()
				if accessToken == "" {
					logger.Error(refreshPuidErrorMessage)
					return
				}

				puid, err := authenticator.GetPUID()
				if err != nil {
					logger.Error(refreshPuidErrorMessage)
					return
				}

				PUID = puid

				time.Sleep(time.Hour * 24 * 7)
			}
		}()
	}
}
