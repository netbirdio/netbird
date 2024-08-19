//go:build !(linux && 386) && !freebsd

package main

import (
	"fmt"
	"sort"
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

const (
	allRoutesText                = "All routes"
	overlappingRoutesText        = "Overlapping routes"
	exitNodeRoutesText           = "Exit-node routes"
	allRoutes             filter = "all"
	overlappingRoutes     filter = "overlapping"
	exitNodeRoutes        filter = "exit-node"
	getClientFMT                 = "get client: %v"
)

type filter string

func (s *serviceClient) showRoutesUI() {
	s.wRoutes = s.app.NewWindow("NetBird Routes")

	allGrid := container.New(layout.NewGridLayout(3))
	go s.updateRoutes(allGrid, allRoutes)
	overlappingGrid := container.New(layout.NewGridLayout(3))
	exitNodeGrid := container.New(layout.NewGridLayout(3))
	routeCheckContainer := container.NewVBox()
	tabs := container.NewAppTabs(
		container.NewTabItem(allRoutesText, allGrid),
		container.NewTabItem(overlappingRoutesText, overlappingGrid),
		container.NewTabItem(exitNodeRoutesText, exitNodeGrid),
	)
	tabs.OnSelected = func(item *container.TabItem) {
		s.updateRoutesBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
	}
	tabs.OnUnselected = func(item *container.TabItem) {
		grid, _ := getGridAndFilterFromTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
		grid.Objects = nil
	}

	routeCheckContainer.Add(tabs)
	scrollContainer := container.NewVScroll(routeCheckContainer)
	scrollContainer.SetMinSize(fyne.NewSize(200, 300))

	buttonBox := container.NewHBox(
		layout.NewSpacer(),
		widget.NewButton("Refresh", func() {
			s.updateRoutesBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
		}),
		widget.NewButton("Select all", func() {
			_, f := getGridAndFilterFromTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
			s.selectAllFilteredRoutes(f)
			s.updateRoutesBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
		}),
		widget.NewButton("Deselect All", func() {
			_, f := getGridAndFilterFromTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
			s.deselectAllFilteredRoutes(f)
			s.updateRoutesBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
		}),
		layout.NewSpacer(),
	)

	content := container.NewBorder(nil, buttonBox, nil, nil, scrollContainer)

	s.wRoutes.SetContent(content)
	s.wRoutes.Show()

	s.startAutoRefresh(10*time.Second, tabs, allGrid, overlappingGrid, exitNodeGrid)
}

func (s *serviceClient) updateRoutes(grid *fyne.Container, f filter) {
	grid.Objects = nil
	grid.Refresh()
	idHeader := widget.NewLabelWithStyle("      ID", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	networkHeader := widget.NewLabelWithStyle("Network/Domains", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	resolvedIPsHeader := widget.NewLabelWithStyle("Resolved IPs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	grid.Add(idHeader)
	grid.Add(networkHeader)
	grid.Add(resolvedIPsHeader)

	filteredRoutes, err := s.getFilteredRoutes(f)
	if err != nil {
		return
	}

	sortRoutesByIDs(filteredRoutes)

	for _, route := range filteredRoutes {
		r := route

		checkBox := widget.NewCheck(r.GetID(), func(checked bool) {
			s.selectRoute(r.ID, checked)
		})
		checkBox.Checked = route.Selected
		checkBox.Resize(fyne.NewSize(20, 20))
		checkBox.Refresh()

		grid.Add(checkBox)
		network := r.GetNetwork()
		domains := r.GetDomains()

		if len(domains) == 0 {
			grid.Add(widget.NewLabel(network))
			grid.Add(widget.NewLabel(""))
			continue
		}

		// our selectors are only for display
		noopFunc := func(_ string) {
			// do nothing
		}

		domainsSelector := widget.NewSelect(domains, noopFunc)
		domainsSelector.Selected = domains[0]
		grid.Add(domainsSelector)

		var resolvedIPsList []string
		for _, domain := range domains {
			if ipList, exists := r.GetResolvedIPs()[domain]; exists {
				resolvedIPsList = append(resolvedIPsList, fmt.Sprintf("%s: %s", domain, strings.Join(ipList.GetIps(), ", ")))
			}
		}

		if len(resolvedIPsList) == 0 {
			grid.Add(widget.NewLabel(""))
			continue
		}

		// TODO: limit width within the selector display
		resolvedIPsSelector := widget.NewSelect(resolvedIPsList, noopFunc)
		resolvedIPsSelector.Selected = resolvedIPsList[0]
		resolvedIPsSelector.Resize(fyne.NewSize(100, 100))
		grid.Add(resolvedIPsSelector)
	}

	s.wRoutes.Content().Refresh()
	grid.Refresh()
}

func (s *serviceClient) getFilteredRoutes(f filter) ([]*proto.Route, error) {
	routes, err := s.fetchRoutes()
	if err != nil {
		log.Errorf(getClientFMT, err)
		s.showError(fmt.Errorf(getClientFMT, err))
		return nil, err
	}
	switch f {
	case overlappingRoutes:
		return getOverlappingRoutes(routes), nil
	case exitNodeRoutes:
		return getExitNodeRoutes(routes), nil
	default:
	}
	return routes, nil
}

func getOverlappingRoutes(routes []*proto.Route) []*proto.Route {
	var filteredRoutes []*proto.Route
	existingRange := make(map[string][]*proto.Route)
	for _, route := range routes {
		if len(route.Domains) > 0 {
			continue
		}
		if r, exists := existingRange[route.GetNetwork()]; exists {
			r = append(r, route)
			existingRange[route.GetNetwork()] = r
		} else {
			existingRange[route.GetNetwork()] = []*proto.Route{route}
		}
	}
	for _, r := range existingRange {
		if len(r) > 1 {
			filteredRoutes = append(filteredRoutes, r...)
		}
	}
	return filteredRoutes
}

func getExitNodeRoutes(routes []*proto.Route) []*proto.Route {
	var filteredRoutes []*proto.Route
	for _, route := range routes {
		if route.Network == "0.0.0.0/0" {
			filteredRoutes = append(filteredRoutes, route)
		}
	}
	return filteredRoutes
}

func sortRoutesByIDs(routes []*proto.Route) {
	sort.Slice(routes, func(i, j int) bool {
		return strings.ToLower(routes[i].GetID()) < strings.ToLower(routes[j].GetID())
	})
}

func (s *serviceClient) fetchRoutes() ([]*proto.Route, error) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		return nil, fmt.Errorf(getClientFMT, err)
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
		log.Errorf(getClientFMT, err)
		s.showError(fmt.Errorf(getClientFMT, err))
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

func (s *serviceClient) selectAllFilteredRoutes(f filter) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf(getClientFMT, err)
		return
	}

	req := s.getRoutesRequest(f, true)
	if _, err := conn.SelectRoutes(s.ctx, req); err != nil {
		log.Errorf("failed to select all routes: %v", err)
		s.showError(fmt.Errorf("failed to select all routes: %v", err))
		return
	}

	log.Debug("All routes selected")
}

func (s *serviceClient) deselectAllFilteredRoutes(f filter) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf(getClientFMT, err)
		return
	}

	req := s.getRoutesRequest(f, false)
	if _, err := conn.DeselectRoutes(s.ctx, req); err != nil {
		log.Errorf("failed to deselect all routes: %v", err)
		s.showError(fmt.Errorf("failed to deselect all routes: %v", err))
		return
	}

	log.Debug("All routes deselected")
}

func (s *serviceClient) getRoutesRequest(f filter, appendRoute bool) *proto.SelectRoutesRequest {
	req := &proto.SelectRoutesRequest{}
	if f == allRoutes {
		req.All = true
	} else {
		routes, err := s.getFilteredRoutes(f)
		if err != nil {
			return nil
		}
		for _, route := range routes {
			req.RouteIDs = append(req.RouteIDs, route.GetID())
		}
		req.Append = appendRoute
	}
	return req
}

func (s *serviceClient) showError(err error) {
	wrappedMessage := wrapText(err.Error(), 50)

	dialog.ShowError(fmt.Errorf("%s", wrappedMessage), s.wRoutes)
}

func (s *serviceClient) startAutoRefresh(interval time.Duration, tabs *container.AppTabs, allGrid, overlappingGrid, exitNodesGrid *fyne.Container) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			s.updateRoutesBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodesGrid)
		}
	}()

	s.wRoutes.SetOnClosed(func() {
		ticker.Stop()
	})
}

func (s *serviceClient) updateRoutesBasedOnDisplayTab(tabs *container.AppTabs, allGrid, overlappingGrid, exitNodesGrid *fyne.Container) {
	grid, f := getGridAndFilterFromTab(tabs, allGrid, overlappingGrid, exitNodesGrid)
	s.wRoutes.Content().Refresh()
	s.updateRoutes(grid, f)
}

func getGridAndFilterFromTab(tabs *container.AppTabs, allGrid, overlappingGrid, exitNodesGrid *fyne.Container) (*fyne.Container, filter) {
	switch tabs.Selected().Text {
	case overlappingRoutesText:
		return overlappingGrid, overlappingRoutes
	case exitNodeRoutesText:
		return exitNodesGrid, exitNodeRoutes
	default:
		return allGrid, allRoutes
	}
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
