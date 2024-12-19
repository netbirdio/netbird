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
	allNetworksText                = "All networks"
	overlappingNetworksText        = "Overlapping networks"
	exitNodeNetworksText           = "Exit-node networks"
	allNetworks             filter = "all"
	overlappingNetworks     filter = "overlapping"
	exitNodeNetworks        filter = "exit-node"
	getClientFMT                   = "get client: %v"
)

type filter string

func (s *serviceClient) showNetworksUI() {
	s.wRoutes = s.app.NewWindow("Networks")

	allGrid := container.New(layout.NewGridLayout(3))
	go s.updateNetworks(allGrid, allNetworks)
	overlappingGrid := container.New(layout.NewGridLayout(3))
	exitNodeGrid := container.New(layout.NewGridLayout(3))
	routeCheckContainer := container.NewVBox()
	tabs := container.NewAppTabs(
		container.NewTabItem(allNetworksText, allGrid),
		container.NewTabItem(overlappingNetworksText, overlappingGrid),
		container.NewTabItem(exitNodeNetworksText, exitNodeGrid),
	)
	tabs.OnSelected = func(item *container.TabItem) {
		s.updateNetworksBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
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
			s.updateNetworksBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
		}),
		widget.NewButton("Select all", func() {
			_, f := getGridAndFilterFromTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
			s.selectAllFilteredNetworks(f)
			s.updateNetworksBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
		}),
		widget.NewButton("Deselect All", func() {
			_, f := getGridAndFilterFromTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
			s.deselectAllFilteredNetworks(f)
			s.updateNetworksBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodeGrid)
		}),
		layout.NewSpacer(),
	)

	content := container.NewBorder(nil, buttonBox, nil, nil, scrollContainer)

	s.wRoutes.SetContent(content)
	s.wRoutes.Show()

	s.startAutoRefresh(10*time.Second, tabs, allGrid, overlappingGrid, exitNodeGrid)
}

func (s *serviceClient) updateNetworks(grid *fyne.Container, f filter) {
	grid.Objects = nil
	grid.Refresh()
	idHeader := widget.NewLabelWithStyle("      ID", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	networkHeader := widget.NewLabelWithStyle("Range/Domains", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	resolvedIPsHeader := widget.NewLabelWithStyle("Resolved IPs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	grid.Add(idHeader)
	grid.Add(networkHeader)
	grid.Add(resolvedIPsHeader)

	filteredRoutes, err := s.getFilteredNetworks(f)
	if err != nil {
		return
	}

	sortNetworksByIDs(filteredRoutes)

	for _, route := range filteredRoutes {
		r := route

		checkBox := widget.NewCheck(r.GetID(), func(checked bool) {
			s.selectNetwork(r.ID, checked)
		})
		checkBox.Checked = route.Selected
		checkBox.Resize(fyne.NewSize(20, 20))
		checkBox.Refresh()

		grid.Add(checkBox)
		network := r.GetRange()
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
		for domain, ipList := range r.GetResolvedIPs() {
			resolvedIPsList = append(resolvedIPsList, fmt.Sprintf("%s: %s", domain, strings.Join(ipList.GetIps(), ", ")))
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

func (s *serviceClient) getFilteredNetworks(f filter) ([]*proto.Network, error) {
	routes, err := s.fetchNetworks()
	if err != nil {
		log.Errorf(getClientFMT, err)
		s.showError(fmt.Errorf(getClientFMT, err))
		return nil, err
	}
	switch f {
	case overlappingNetworks:
		return getOverlappingNetworks(routes), nil
	case exitNodeNetworks:
		return getExitNodeNetworks(routes), nil
	default:
	}
	return routes, nil
}

func getOverlappingNetworks(routes []*proto.Network) []*proto.Network {
	var filteredRoutes []*proto.Network
	existingRange := make(map[string][]*proto.Network)
	for _, route := range routes {
		if len(route.Domains) > 0 {
			continue
		}
		if r, exists := existingRange[route.GetRange()]; exists {
			r = append(r, route)
			existingRange[route.GetRange()] = r
		} else {
			existingRange[route.GetRange()] = []*proto.Network{route}
		}
	}
	for _, r := range existingRange {
		if len(r) > 1 {
			filteredRoutes = append(filteredRoutes, r...)
		}
	}
	return filteredRoutes
}

func getExitNodeNetworks(routes []*proto.Network) []*proto.Network {
	var filteredRoutes []*proto.Network
	for _, route := range routes {
		if route.Range == "0.0.0.0/0" {
			filteredRoutes = append(filteredRoutes, route)
		}
	}
	return filteredRoutes
}

func sortNetworksByIDs(routes []*proto.Network) {
	sort.Slice(routes, func(i, j int) bool {
		return strings.ToLower(routes[i].GetID()) < strings.ToLower(routes[j].GetID())
	})
}

func (s *serviceClient) fetchNetworks() ([]*proto.Network, error) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		return nil, fmt.Errorf(getClientFMT, err)
	}

	resp, err := conn.ListNetworks(s.ctx, &proto.ListNetworksRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %v", err)
	}

	return resp.Routes, nil
}

func (s *serviceClient) selectNetwork(id string, checked bool) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf(getClientFMT, err)
		s.showError(fmt.Errorf(getClientFMT, err))
		return
	}

	req := &proto.SelectNetworksRequest{
		NetworkIDs: []string{id},
		Append:     checked,
	}

	if checked {
		if _, err := conn.SelectNetworks(s.ctx, req); err != nil {
			log.Errorf("failed to select network: %v", err)
			s.showError(fmt.Errorf("failed to select network: %v", err))
			return
		}
		log.Infof("Route %s selected", id)
	} else {
		if _, err := conn.DeselectNetworks(s.ctx, req); err != nil {
			log.Errorf("failed to deselect network: %v", err)
			s.showError(fmt.Errorf("failed to deselect network: %v", err))
			return
		}
		log.Infof("Network %s deselected", id)
	}
}

func (s *serviceClient) selectAllFilteredNetworks(f filter) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf(getClientFMT, err)
		return
	}

	req := s.getNetworksRequest(f, true)
	if _, err := conn.SelectNetworks(s.ctx, req); err != nil {
		log.Errorf("failed to select all networks: %v", err)
		s.showError(fmt.Errorf("failed to select all networks: %v", err))
		return
	}

	log.Debug("All networks selected")
}

func (s *serviceClient) deselectAllFilteredNetworks(f filter) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf(getClientFMT, err)
		return
	}

	req := s.getNetworksRequest(f, false)
	if _, err := conn.DeselectNetworks(s.ctx, req); err != nil {
		log.Errorf("failed to deselect all networks: %v", err)
		s.showError(fmt.Errorf("failed to deselect all networks: %v", err))
		return
	}

	log.Debug("All networks deselected")
}

func (s *serviceClient) getNetworksRequest(f filter, appendRoute bool) *proto.SelectNetworksRequest {
	req := &proto.SelectNetworksRequest{}
	if f == allNetworks {
		req.All = true
	} else {
		routes, err := s.getFilteredNetworks(f)
		if err != nil {
			return nil
		}
		for _, route := range routes {
			req.NetworkIDs = append(req.NetworkIDs, route.GetID())
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
			s.updateNetworksBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodesGrid)
		}
	}()

	s.wRoutes.SetOnClosed(func() {
		ticker.Stop()
	})
}

func (s *serviceClient) updateNetworksBasedOnDisplayTab(tabs *container.AppTabs, allGrid, overlappingGrid, exitNodesGrid *fyne.Container) {
	grid, f := getGridAndFilterFromTab(tabs, allGrid, overlappingGrid, exitNodesGrid)
	s.wRoutes.Content().Refresh()
	s.updateNetworks(grid, f)
}

func getGridAndFilterFromTab(tabs *container.AppTabs, allGrid, overlappingGrid, exitNodesGrid *fyne.Container) (*fyne.Container, filter) {
	switch tabs.Selected().Text {
	case overlappingNetworksText:
		return overlappingGrid, overlappingNetworks
	case exitNodeNetworksText:
		return exitNodesGrid, exitNodeNetworks
	default:
		return allGrid, allNetworks
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
