package chatgpt

import (
	"fmt"
	"os"
	"time"

	"github.com/PuerkitoBio/goquery"
	http "github.com/bogdanfinn/fhttp"
    tls_client "github.com/bogdanfinn/tls-client"
	"github.com/linweiyuan/go-chatgpt-api/api"
	"github.com/linweiyuan/go-logger/logger"
)

const (
	healthCheckUrl         = "https://chat.openai.com/backend-api/accounts/check"
	errorHintBlock         = "looks like you have bean blocked by OpenAI, please change to a new IP or have a try with WARP"
	errorHintFailedToStart = "failed to start, please try again later: %s"
	sleepHours             = 8760 // 365 days
)

func init() {
	proxyUrl := os.Getenv("PROXY")
	if proxyUrl != "" {
		logger.Info("PROXY: " + proxyUrl)
		api.Client.SetProxy(proxyUrl)

		for {
		    logger.Info("Start Health Check: " + proxyUrl)
			resp, err := healthCheck()
			if err != nil {
				// wait for proxy to be ready
				time.Sleep(time.Second)
				fmt.Println("Health Check Error:", err.Error())
				continue
			}

			checkHealthCheckStatus(resp)
			break
		}
	} else {
		resp, err := healthCheck()
		if err != nil {
			logger.Error("failed to health check: " + err.Error())
			os.Exit(1)
		}

		checkHealthCheckStatus(resp)
	}
}

func healthCheck() (resp *http.Response, err error) {
    logger.Info("Send Health Check Request")
	req, _ := http.NewRequest(http.MethodGet, healthCheckUrl, nil)
	req.Header.Set("User-Agent", api.UserAgent)
	resp, err = api.Client.Do(req)
	logger.Info("Finish Health Check Request")
	return
}

func getHttpClient() tls_client.HttpClient {
	client, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(3),
	}...)
	return client
}

func checkHealthCheckStatus(resp *http.Response) {
	if resp != nil {
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			logger.Info(api.ReadyHint)
		} else {
			doc, _ := goquery.NewDocumentFromReader(resp.Body)
			alert := doc.Find(".message").Text()
			if alert != "" {
				logger.Error(errorHintBlock)
			} else {
				logger.Error(fmt.Sprintf(errorHintFailedToStart, resp.Status))
			}
			time.Sleep(time.Hour * sleepHours)
			os.Exit(1)
		}
	}
}
