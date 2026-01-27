//go:build !(linux && 386)

package main

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"fyne.io/systray"
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

type exitNodeState struct {
	id       string
	selected bool
}

func (s *serviceClient) showNetworksUI() {
	s.wNetworks = s.app.NewWindow("Networks")
	s.wNetworks.SetOnClosed(s.cancel)

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

	s.wNetworks.SetContent(content)
	s.wNetworks.Show()

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

	s.wNetworks.Content().Refresh()
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
		log.Infof("Network '%s' selected", id)
	} else {
		if _, err := conn.DeselectNetworks(s.ctx, req); err != nil {
			log.Errorf("failed to deselect network: %v", err)
			s.showError(fmt.Errorf("failed to deselect network: %v", err))
			return
		}
		log.Infof("Network '%s' deselected", id)
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

	dialog.ShowError(fmt.Errorf("%s", wrappedMessage), s.wNetworks)
}

func (s *serviceClient) startAutoRefresh(interval time.Duration, tabs *container.AppTabs, allGrid, overlappingGrid, exitNodesGrid *fyne.Container) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			s.updateNetworksBasedOnDisplayTab(tabs, allGrid, overlappingGrid, exitNodesGrid)
		}
	}()

	s.wNetworks.SetOnClosed(func() {
		ticker.Stop()
		s.cancel()
	})
}

func (s *serviceClient) updateNetworksBasedOnDisplayTab(tabs *container.AppTabs, allGrid, overlappingGrid, exitNodesGrid *fyne.Container) {
	grid, f := getGridAndFilterFromTab(tabs, allGrid, overlappingGrid, exitNodesGrid)
	s.wNetworks.Content().Refresh()
	s.updateNetworks(grid, f)
}

func (s *serviceClient) updateExitNodes() {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return
	}
	exitNodes, err := s.getExitNodes(conn)
	if err != nil {
		log.Errorf("get exit nodes: %v", err)
		return
	}

	s.exitNodeMu.Lock()
	defer s.exitNodeMu.Unlock()

	s.recreateExitNodeMenu(exitNodes)

	if len(s.mExitNodeItems) > 0 {
		s.mExitNode.Enable()
	} else {
		s.mExitNode.Disable()
	}
}

func (s *serviceClient) recreateExitNodeMenu(exitNodes []*proto.Network) {
	var exitNodeIDs []exitNodeState
	for _, node := range exitNodes {
		exitNodeIDs = append(exitNodeIDs, exitNodeState{
			id:       node.ID,
			selected: node.Selected,
		})
	}

	sort.Slice(exitNodeIDs, func(i, j int) bool {
		return exitNodeIDs[i].id < exitNodeIDs[j].id
	})
	if slices.Equal(s.exitNodeStates, exitNodeIDs) {
		log.Debug("Exit node menu already up to date")
		return
	}

	for _, node := range s.mExitNodeItems {
		node.cancel()
		node.Hide()
		node.Remove()
	}
	s.mExitNodeItems = nil
	if s.mExitNodeDeselectAll != nil {
		s.mExitNodeDeselectAll.Remove()
		s.mExitNodeDeselectAll = nil
	}

	if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" {
		s.mExitNode.Remove()
		s.mExitNode = systray.AddMenuItem("Exit Node", disabledMenuDescr)
	}

	var showDeselectAll bool

	for _, node := range exitNodes {
		if node.Selected {
			showDeselectAll = true
		}

		menuItem := s.mExitNode.AddSubMenuItemCheckbox(
			node.ID,
			fmt.Sprintf("Use exit node %s", node.ID),
			node.Selected,
		)

		ctx, cancel := context.WithCancel(s.ctx)
		s.mExitNodeItems = append(s.mExitNodeItems, menuHandler{
			MenuItem: menuItem,
			cancel:   cancel,
		})
		go s.handleChecked(ctx, node.ID, menuItem)
	}

	s.exitNodeStates = exitNodeIDs

	if showDeselectAll {
		s.mExitNode.AddSeparator()
		deselectAllItem := s.mExitNode.AddSubMenuItem("Deselect All", "Deselect All")
		s.mExitNodeDeselectAll = deselectAllItem
		go func() {
			for {
				_, ok := <-deselectAllItem.ClickedCh
				if !ok {
					// channel closed: exit the goroutine
					return
				}
				exitNodes, err := s.handleExitNodeMenuDeselectAll()
				if err != nil {
					log.Warnf("failed to handle deselect all exit nodes: %v", err)
				} else {
					s.exitNodeMu.Lock()
					s.recreateExitNodeMenu(exitNodes)
					s.exitNodeMu.Unlock()
				}
			}

		}()
	}

}

func (s *serviceClient) getExitNodes(conn proto.DaemonServiceClient) ([]*proto.Network, error) {
	ctx, cancel := context.WithTimeout(s.ctx, defaultFailTimeout)
	defer cancel()

	resp, err := conn.ListNetworks(ctx, &proto.ListNetworksRequest{})
	if err != nil {
		return nil, fmt.Errorf("list networks: %v", err)
	}

	var exitNodes []*proto.Network
	for _, network := range resp.Routes {
		if network.Range == "0.0.0.0/0" {
			exitNodes = append(exitNodes, network)
		}
	}
	return exitNodes, nil
}

func (s *serviceClient) handleChecked(ctx context.Context, id string, item *systray.MenuItem) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-item.ClickedCh:
			if !ok {
				return
			}
			if err := s.toggleExitNode(id, item); err != nil {
				log.Errorf("failed to toggle exit node: %v", err)
				continue
			}
		}
	}
}

func (s *serviceClient) handleExitNodeMenuDeselectAll() ([]*proto.Network, error) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		return nil, fmt.Errorf("get client: %v", err)
	}

	exitNodes, err := s.getExitNodes(conn)
	if err != nil {
		return nil, fmt.Errorf("get exit nodes: %v", err)
	}

	var ids []string
	for _, e := range exitNodes {
		if e.Selected {
			ids = append(ids, e.ID)
		}
	}

	// deselect selected exit nodes
	if err := s.deselectOtherExitNodes(conn, ids); err != nil {
		return nil, err
	}

	updatedExitNodes, err := s.getExitNodes(conn)
	if err != nil {
		return nil, fmt.Errorf("re-fetch exit nodes: %v", err)
	}

	return updatedExitNodes, nil
}

// Add function to toggle exit node selection
func (s *serviceClient) toggleExitNode(nodeID string, item *systray.MenuItem) error {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		return fmt.Errorf("get client: %v", err)
	}

	log.Infof("Toggling exit node '%s'", nodeID)

	s.exitNodeMu.Lock()
	defer s.exitNodeMu.Unlock()

	exitNodes, err := s.getExitNodes(conn)
	if err != nil {
		return fmt.Errorf("get exit nodes: %v", err)
	}

	var exitNode *proto.Network
	// find other selected nodes and ours
	ids := make([]string, 0, len(exitNodes))
	for _, node := range exitNodes {
		if node.ID == nodeID {
			// preserve original state
			cp := *node //nolint:govet
			exitNode = &cp

			// set desired state for recreation
			node.Selected = true
			continue
		}
		if node.Selected {
			ids = append(ids, node.ID)

			// set desired state for recreation
			node.Selected = false
		}
	}

	// exit node is the only selected node, deselect it
	deselectAll := item.Checked() && len(ids) == 0
	if deselectAll {
		ids = append(ids, nodeID)
		for _, node := range exitNodes {
			if node.ID == nodeID {
				// set desired state for recreation
				node.Selected = false
			}
		}
	}

	// deselect all other selected exit nodes
	if err := s.deselectOtherExitNodes(conn, ids); err != nil {
		return err
	}

	if !deselectAll {
		if err := s.selectNewExitNode(conn, exitNode, nodeID, item); err != nil {
			return err
		}
	}

	// linux/bsd doesn't handle Check/Uncheck well, so we recreate the menu
	if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" {
		s.recreateExitNodeMenu(exitNodes)
	}

	return nil
}

func (s *serviceClient) deselectOtherExitNodes(conn proto.DaemonServiceClient, ids []string) error {
	// deselect all other selected exit nodes
	if len(ids) > 0 {
		deselectReq := &proto.SelectNetworksRequest{
			NetworkIDs: ids,
		}
		if _, err := conn.DeselectNetworks(s.ctx, deselectReq); err != nil {
			return fmt.Errorf("deselect networks: %v", err)
		}

		log.Infof("Deselected exit nodes: %v", ids)
	}

	// uncheck all other exit node menu items
	for _, i := range s.mExitNodeItems {
		i.Uncheck()
		log.Infof("Unchecked exit node %v", i)
	}

	return nil
}

func (s *serviceClient) selectNewExitNode(conn proto.DaemonServiceClient, exitNode *proto.Network, nodeID string, item *systray.MenuItem) error {
	if exitNode != nil && !exitNode.Selected {
		selectReq := &proto.SelectNetworksRequest{
			NetworkIDs: []string{exitNode.ID},
			Append:     true,
		}
		if _, err := conn.SelectNetworks(s.ctx, selectReq); err != nil {
			return fmt.Errorf("select network: %v", err)
		}

		log.Infof("Selected exit node '%s'", nodeID)
	}

	item.Check()
	log.Infof("Checked exit node '%s'", nodeID)

	return nil
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
