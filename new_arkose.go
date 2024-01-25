package main

import (
	// 	"fmt"

	"encoding/json"
	"fmt"
	"github.com/xqdoo00o/funcaptcha"
	"net/http"
	"os"
	"time"
)

type TokenResponse struct {
	Code    int    `json:"code"`
	Created int64  `json:"created"`
	Msg     string `json:"msg"`
	Token   string `json:"token"`
}

func timestampToDatetime(timestamp int64) string {
	t := time.Unix(timestamp, 0)
	return t.Format("2006-01-02 15:04:05")
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	version := 4 // 0 - Auth, 3 - 3.5, 4 - 4
	token, _ := funcaptcha.GetOpenAIToken(version, "", "")

	datetime := timestampToDatetime(time.Now().Unix())
	fmt.Printf("Time: %s \nGenerated Token: %s\n", datetime, token)

	response := TokenResponse{
		Code:    1,
		Created: time.Now().Unix(),
		Msg:     "success",
		Token:   token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	port := os.Getenv("ARKOSE_PORT") // 从环境变量中获取端口
	if port == "" {
		port = "8080" // 默认端口为8080
	}
	http.HandleFunc("/token", tokenHandler)
	addr := ":" + port
	fmt.Printf("Listening on %s...\n", addr)
	http.ListenAndServe(addr, nil)
}
