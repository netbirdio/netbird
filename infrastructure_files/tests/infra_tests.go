package main

import (
	"context"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"log"
	"net/url"
	"os"
	"time"
)

func main() {
	ciAudience := os.Getenv("CI_NETBIRD_AUTH0_AUDIENCE")
	// create context
	parentCtx, parentCancel := chromedp.NewContext(context.Background(), chromedp.WithLogf(log.Printf))
	defer parentCancel()
	ctx, cancel := context.WithTimeout(parentCtx, 45*time.Second)
	defer cancel()

	var urlstr string

	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate("http://localhost:3000/peers"),
		chromedp.WaitVisible(`#or-separator-login`),
		chromedp.Location(&urlstr),
	)
	if err != nil {
		log.Fatal(err)
	}
	parsedURL, err := url.ParseRequestURI(urlstr)
	values := parsedURL.Query()
	if ciAudience != values.Get("audience") {
		log.Fatalf("unable to find expected audience from local call: %s", values.Get("audience"))
	}
	log.Print("no errors found")
}
