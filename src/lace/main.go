package main

import (
	"github.com/gin-gonic/gin"
	"lace/api"
	"lace/app"
	_ "lace/store/mysqlstore"
)

var db = make(map[string]string)

func setupRouter(app *app.App) *gin.Engine {
	api := api.Init(app)
	return api.Engin
}

func main() {
	app := app.NewApp()
	app.Initialize()
	r := setupRouter(app)
	// Listen and Server in 0.0.0.0:8080
	r.Run(":8080")
}
