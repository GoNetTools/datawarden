// Examples for the Go web request sources (internal/rules/builtin/requests.yaml).
package examples

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/labstack/echo/v4"
)

type signupRequest struct{ Plan string }

func netHTTP(w http.ResponseWriter, r *http.Request) {
	// ruleid: src.go.http_request
	body, _ := io.ReadAll(r.Body)
	// ruleid: log.go.stdlib
	log.Printf("signup %s", body)
	// ruleid: src.go.http_request, log.go.stdlib
	log.Println(r.Form)
	// ok: src.go.http_request
	log.Println(r.PostForm.Get("page"))
}

func netHTTPDecode(r *http.Request) {
	var req signupRequest
	// ruleid: src.go.http_request
	_ = json.NewDecoder(r.Body).Decode(&req)
	// ruleid: log.go.stdlib
	log.Println(req)
}

func netHTTPFormValue(r *http.Request, field string) {
	// ruleid: src.go.http_request, log.go.stdlib
	log.Println(r.FormValue(field))
	// ok: src.go.http_request
	log.Println(r.FormValue("page"))
}

func ginHandler(c *gin.Context) {
	// ruleid: src.go.gin_request
	raw, _ := c.GetRawData()
	// ruleid: log.go.stdlib
	log.Printf("%s", raw)
	// ok: src.go.gin_request
	log.Println(c.PostForm("page"))
}

func ginBind(c *gin.Context) {
	var req signupRequest
	// ruleid: src.go.gin_bind
	if err := c.ShouldBindJSON(&req); err != nil {
		return
	}
	// ruleid: log.go.stdlib
	log.Println(req)
}

func echoHandler(c echo.Context) error {
	// ruleid: src.go.echo_request
	form, _ := c.FormParams()
	// ruleid: log.go.stdlib
	log.Println(form)
	return nil
}

func echoBind(c echo.Context) error {
	var req signupRequest
	// ruleid: src.go.echo_bind
	if err := c.Bind(&req); err != nil {
		return err
	}
	// ruleid: log.go.stdlib
	log.Println(req)
	return nil
}

func chiHandler(r *http.Request, name string) {
	// ruleid: src.go.chi_url_param, log.go.stdlib
	log.Println(chi.URLParam(r, name))
	// ok: src.go.chi_url_param
	log.Println(chi.URLParam(r, "id"))
}
