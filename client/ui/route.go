//go:build !(linux && 386)

package main

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

func (s *serviceClient) showRoutesUI() {
	s.wRoutes = s.app.NewWindow("NetBird Routes")

	grid := container.New(layout.NewGridLayout(2))
	go s.updateRoutes(grid)
	routeCheckContainer := container.NewVBox()
	routeCheckContainer.Add(grid)
	scrollContainer := container.NewVScroll(routeCheckContainer)
	scrollContainer.SetMinSize(fyne.NewSize(200, 300))

	buttonBox := container.NewHBox(
		layout.NewSpacer(),
		widget.NewButton("Refresh", func() {
			s.updateRoutes(grid)
		}),
		widget.NewButton("Select all", func() {
			s.selectAllRoutes()
			s.updateRoutes(grid)
		}),
		widget.NewButton("Deselect All", func() {
			s.deselectAllRoutes()
			s.updateRoutes(grid)
		}),
		layout.NewSpacer(),
	)

	content := container.NewBorder(nil, buttonBox, nil, nil, scrollContainer)

	s.wRoutes.SetContent(content)
	s.wRoutes.Show()

	s.startAutoRefresh(5*time.Second, grid)
}

func (s *serviceClient) updateRoutes(grid *fyne.Container) {
	routes, err := s.fetchRoutes()
	if err != nil {
		log.Errorf("get client: %v", err)
		s.showError(fmt.Errorf("get client: %v", err))
		return
	}

	grid.Objects = nil
	idHeader := widget.NewLabelWithStyle("      ID", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	networkHeader := widget.NewLabelWithStyle("Network", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	grid.Add(idHeader)
	grid.Add(networkHeader)
	for _, route := range routes {
		r := route

		checkBox := widget.NewCheck(r.ID, func(checked bool) {
			s.selectRoute(r.ID, checked)
		})
		checkBox.Checked = route.Selected
		checkBox.Resize(fyne.NewSize(20, 20))
		checkBox.Refresh()

		grid.Add(checkBox)
		grid.Add(widget.NewLabel(r.Network))
	}

	s.wRoutes.Content().Refresh()
}

func (s *serviceClient) fetchRoutes() ([]*proto.Route, error) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		return nil, fmt.Errorf("get client: %v", err)
	}

	resp, err := conn.ListRoutes(s.ctx, &proto.ListRoutesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %v", err)
	}

	return resp.Routes, nil
}

func (s *serviceClient) selectRoute(id string, checked bool) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		s.showError(fmt.Errorf("get client: %v", err))
		return
	}

	req := &proto.SelectRoutesRequest{
		RouteIDs: []string{id},
		Append:   checked,
	}

	if checked {
		if _, err := conn.SelectRoutes(s.ctx, req); err != nil {
			log.Errorf("failed to select route: %v", err)
			s.showError(fmt.Errorf("failed to select route: %v", err))
			return
		}
		log.Infof("Route %s selected", id)
	} else {
		if _, err := conn.DeselectRoutes(s.ctx, req); err != nil {
			log.Errorf("failed to deselect route: %v", err)
			s.showError(fmt.Errorf("failed to deselect route: %v", err))
			return
		}
		log.Infof("Route %s deselected", id)
	}
}

func (s *serviceClient) selectAllRoutes() {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return
	}

	req := &proto.SelectRoutesRequest{
		All: true,
	}
	if _, err := conn.SelectRoutes(s.ctx, req); err != nil {
		log.Errorf("failed to select all routes: %v", err)
		s.showError(fmt.Errorf("failed to select all routes: %v", err))
		return
	}

	log.Debug("All routes selected")
}

func (s *serviceClient) deselectAllRoutes() {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return
	}

	req := &proto.SelectRoutesRequest{
		All: true,
	}
	if _, err := conn.DeselectRoutes(s.ctx, req); err != nil {
		log.Errorf("failed to deselect all routes: %v", err)
		s.showError(fmt.Errorf("failed to deselect all routes: %v", err))
		return
	}

	log.Debug("All routes deselected")
}

func (s *serviceClient) showError(err error) {
	wrappedMessage := wrapText(err.Error(), 50)

	dialog.ShowError(fmt.Errorf("%s", wrappedMessage), s.wRoutes)
}

func (s *serviceClient) startAutoRefresh(interval time.Duration, grid *fyne.Container) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			s.updateRoutes(grid)
		}
	}()

	s.wRoutes.SetOnClosed(func() {
		ticker.Stop()
	})
}

// wrapText inserts newlines into the text to ensure that each line is
// no longer than 'lineLength' runes.
func wrapText(text string, lineLength int) string {
	var sb strings.Builder
	var currentLineLength int

	for _, runeValue := range text {
		sb.WriteRune(runeValue)
		currentLineLength++

		if currentLineLength >= lineLength || runeValue == '\n' {
			sb.WriteRune('\n')
			currentLineLength = 0
		}
	}

	return sb.String()
}
