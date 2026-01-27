//go:build !(linux && 386)

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	uptypes "github.com/netbirdio/netbird/upload-server/types"
)

// Initial state for the debug collection
type debugInitialState struct {
	wasDown      bool
	logLevel     proto.LogLevel
	isLevelTrace bool
}

// Debug collection parameters
type debugCollectionParams struct {
	duration          time.Duration
	anonymize         bool
	systemInfo        bool
	upload            bool
	uploadURL         string
	enablePersistence bool
}

// UI components for progress tracking
type progressUI struct {
	statusLabel *widget.Label
	progressBar *widget.ProgressBar
	uiControls  []fyne.Disableable
	window      fyne.Window
}

func (s *serviceClient) showDebugUI() {
	w := s.app.NewWindow("NetBird Debug")
	w.SetOnClosed(s.cancel)

	w.Resize(fyne.NewSize(600, 500))
	w.SetFixedSize(true)

	anonymizeCheck := widget.NewCheck("Anonymize sensitive information (public IPs, domains, ...)", nil)
	systemInfoCheck := widget.NewCheck("Include system information (routes, interfaces, ...)", nil)
	systemInfoCheck.SetChecked(true)
	uploadCheck := widget.NewCheck("Upload bundle automatically after creation", nil)
	uploadCheck.SetChecked(true)

	uploadURLLabel := widget.NewLabel("Debug upload URL:")
	uploadURL := widget.NewEntry()
	uploadURL.SetText(uptypes.DefaultBundleURL)
	uploadURL.SetPlaceHolder("Enter upload URL")

	uploadURLContainer := container.NewVBox(
		uploadURLLabel,
		uploadURL,
	)

	uploadCheck.OnChanged = func(checked bool) {
		if checked {
			uploadURLContainer.Show()
		} else {
			uploadURLContainer.Hide()
		}
	}

	debugModeContainer := container.NewHBox()
	runForDurationCheck := widget.NewCheck("Run with trace logs before creating bundle", nil)
	runForDurationCheck.SetChecked(true)

	forLabel := widget.NewLabel("for")

	durationInput := widget.NewEntry()
	durationInput.SetText("1")
	minutesLabel := widget.NewLabel("minute")
	durationInput.Validator = func(s string) error {
		return validateMinute(s, minutesLabel)
	}

	noteLabel := widget.NewLabel("Note: NetBird will be brought up and down during collection")

	runForDurationCheck.OnChanged = func(checked bool) {
		if checked {
			forLabel.Show()
			durationInput.Show()
			minutesLabel.Show()
			noteLabel.Show()
		} else {
			forLabel.Hide()
			durationInput.Hide()
			minutesLabel.Hide()
			noteLabel.Hide()
		}
	}

	debugModeContainer.Add(runForDurationCheck)
	debugModeContainer.Add(forLabel)
	debugModeContainer.Add(durationInput)
	debugModeContainer.Add(minutesLabel)

	statusLabel := widget.NewLabel("")
	statusLabel.Hide()

	progressBar := widget.NewProgressBar()
	progressBar.Hide()

	createButton := widget.NewButton("Create Debug Bundle", nil)

	// UI controls that should be disabled during debug collection
	uiControls := []fyne.Disableable{
		anonymizeCheck,
		systemInfoCheck,
		uploadCheck,
		uploadURL,
		runForDurationCheck,
		durationInput,
		createButton,
	}

	createButton.OnTapped = s.getCreateHandler(
		statusLabel,
		progressBar,
		uploadCheck,
		uploadURL,
		anonymizeCheck,
		systemInfoCheck,
		runForDurationCheck,
		durationInput,
		uiControls,
		w,
	)

	content := container.NewVBox(
		widget.NewLabel("Create a debug bundle to help troubleshoot issues with NetBird"),
		widget.NewLabel(""),
		anonymizeCheck,
		systemInfoCheck,
		uploadCheck,
		uploadURLContainer,
		widget.NewLabel(""),
		debugModeContainer,
		noteLabel,
		widget.NewLabel(""),
		statusLabel,
		progressBar,
		createButton,
	)

	paddedContent := container.NewPadded(content)
	w.SetContent(paddedContent)

	w.Show()
}

func validateMinute(s string, minutesLabel *widget.Label) error {
	if val, err := strconv.Atoi(s); err != nil || val < 1 {
		return fmt.Errorf("must be a number ≥ 1")
	}
	if s == "1" {
		minutesLabel.SetText("minute")
	} else {
		minutesLabel.SetText("minutes")
	}
	return nil
}

// disableUIControls disables the provided UI controls
func disableUIControls(controls []fyne.Disableable) {
	for _, control := range controls {
		control.Disable()
	}
}

// enableUIControls enables the provided UI controls
func enableUIControls(controls []fyne.Disableable) {
	for _, control := range controls {
		control.Enable()
	}
}

func (s *serviceClient) getCreateHandler(
	statusLabel *widget.Label,
	progressBar *widget.ProgressBar,
	uploadCheck *widget.Check,
	uploadURL *widget.Entry,
	anonymizeCheck *widget.Check,
	systemInfoCheck *widget.Check,
	runForDurationCheck *widget.Check,
	duration *widget.Entry,
	uiControls []fyne.Disableable,
	w fyne.Window,
) func() {
	return func() {
		disableUIControls(uiControls)
		statusLabel.Show()

		var url string
		if uploadCheck.Checked {
			url = uploadURL.Text
			if url == "" {
				statusLabel.SetText("Error: Upload URL is required when upload is enabled")
				enableUIControls(uiControls)
				return
			}
		}

		params := &debugCollectionParams{
			anonymize:         anonymizeCheck.Checked,
			systemInfo:        systemInfoCheck.Checked,
			upload:            uploadCheck.Checked,
			uploadURL:         url,
			enablePersistence: true,
		}

		runForDuration := runForDurationCheck.Checked
		if runForDuration {
			minutes, err := time.ParseDuration(duration.Text + "m")
			if err != nil {
				statusLabel.SetText(fmt.Sprintf("Error: Invalid duration: %v", err))
				enableUIControls(uiControls)
				return
			}
			params.duration = minutes

			statusLabel.SetText(fmt.Sprintf("Running in debug mode for %d minutes...", int(minutes.Minutes())))
			progressBar.Show()
			progressBar.SetValue(0)

			go s.handleRunForDuration(
				statusLabel,
				progressBar,
				uiControls,
				w,
				params,
			)
			return
		}

		statusLabel.SetText("Creating debug bundle...")
		go s.handleDebugCreation(
			anonymizeCheck.Checked,
			systemInfoCheck.Checked,
			uploadCheck.Checked,
			url,
			statusLabel,
			uiControls,
			w,
		)
	}
}

func (s *serviceClient) handleRunForDuration(
	statusLabel *widget.Label,
	progressBar *widget.ProgressBar,
	uiControls []fyne.Disableable,
	w fyne.Window,
	params *debugCollectionParams,
) {
	progressUI := &progressUI{
		statusLabel: statusLabel,
		progressBar: progressBar,
		uiControls:  uiControls,
		window:      w,
	}

	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		handleError(progressUI, fmt.Sprintf("Failed to get client for debug: %v", err))
		return
	}

	initialState, err := s.getInitialState(conn)
	if err != nil {
		handleError(progressUI, err.Error())
		return
	}

	defer s.restoreServiceState(conn, initialState)

	if err := s.collectDebugData(conn, initialState, params, progressUI); err != nil {
		handleError(progressUI, err.Error())
		return
	}

	if err := s.createDebugBundleFromCollection(conn, params, progressUI); err != nil {
		handleError(progressUI, err.Error())
		return
	}

	progressUI.statusLabel.SetText("Bundle created successfully")
}

// Get initial state of the service
func (s *serviceClient) getInitialState(conn proto.DaemonServiceClient) (*debugInitialState, error) {
	statusResp, err := conn.Status(s.ctx, &proto.StatusRequest{})
	if err != nil {
		return nil, fmt.Errorf(" get status: %v", err)
	}

	logLevelResp, err := conn.GetLogLevel(s.ctx, &proto.GetLogLevelRequest{})
	if err != nil {
		return nil, fmt.Errorf("get log level: %v", err)
	}

	wasDown := statusResp.Status != string(internal.StatusConnected) &&
		statusResp.Status != string(internal.StatusConnecting)

	initialLogLevel := logLevelResp.GetLevel()
	initialLevelTrace := initialLogLevel >= proto.LogLevel_TRACE

	return &debugInitialState{
		wasDown:      wasDown,
		logLevel:     initialLogLevel,
		isLevelTrace: initialLevelTrace,
	}, nil
}

// Handle progress tracking during collection
func startProgressTracker(ctx context.Context, wg *sync.WaitGroup, duration time.Duration, progress *progressUI) {
	progress.progressBar.Show()
	progress.progressBar.SetValue(0)

	startTime := time.Now()
	endTime := startTime.Add(duration)
	wg.Add(1)

	go func() {
		defer wg.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				remaining := time.Until(endTime)
				if remaining <= 0 {
					remaining = 0
				}

				elapsed := time.Since(startTime)
				progressVal := float64(elapsed) / float64(duration)
				if progressVal > 1.0 {
					progressVal = 1.0
				}

				progress.progressBar.SetValue(progressVal)
				progress.statusLabel.SetText(fmt.Sprintf("Running with trace logs... %s remaining", formatDuration(remaining)))
			}
		}
	}()

}

func (s *serviceClient) configureServiceForDebug(
	conn proto.DaemonServiceClient,
	state *debugInitialState,
	enablePersistence bool,
) error {
	if state.wasDown {
		if _, err := conn.Up(s.ctx, &proto.UpRequest{}); err != nil {
			return fmt.Errorf("bring service up: %v", err)
		}
		log.Info("Service brought up for debug")
		time.Sleep(time.Second * 10)
	}

	if !state.isLevelTrace {
		if _, err := conn.SetLogLevel(s.ctx, &proto.SetLogLevelRequest{Level: proto.LogLevel_TRACE}); err != nil {
			return fmt.Errorf("set log level to TRACE: %v", err)
		}
		log.Info("Log level set to TRACE for debug")
	}

	if _, err := conn.Down(s.ctx, &proto.DownRequest{}); err != nil {
		return fmt.Errorf("bring service down: %v", err)
	}
	time.Sleep(time.Second)

	if enablePersistence {
		if _, err := conn.SetSyncResponsePersistence(s.ctx, &proto.SetSyncResponsePersistenceRequest{
			Enabled: true,
		}); err != nil {
			return fmt.Errorf("enable sync response persistence: %v", err)
		}
		log.Info("Sync response persistence enabled for debug")
	}

	if _, err := conn.Up(s.ctx, &proto.UpRequest{}); err != nil {
		return fmt.Errorf("bring service back up: %v", err)
	}
	time.Sleep(time.Second * 3)

	if _, err := conn.StartCPUProfile(s.ctx, &proto.StartCPUProfileRequest{}); err != nil {
		log.Warnf("failed to start CPU profiling: %v", err)
	}

	return nil
}

func (s *serviceClient) collectDebugData(
	conn proto.DaemonServiceClient,
	state *debugInitialState,
	params *debugCollectionParams,
	progress *progressUI,
) error {
	ctx, cancel := context.WithTimeout(s.ctx, params.duration)
	defer cancel()
	var wg sync.WaitGroup
	startProgressTracker(ctx, &wg, params.duration, progress)

	if err := s.configureServiceForDebug(conn, state, params.enablePersistence); err != nil {
		return err
	}

	wg.Wait()
	progress.progressBar.Hide()
	progress.statusLabel.SetText("Collecting debug data...")

	if _, err := conn.StopCPUProfile(s.ctx, &proto.StopCPUProfileRequest{}); err != nil {
		log.Warnf("failed to stop CPU profiling: %v", err)
	}

	return nil
}

// Create the debug bundle with collected data
func (s *serviceClient) createDebugBundleFromCollection(
	conn proto.DaemonServiceClient,
	params *debugCollectionParams,
	progress *progressUI,
) error {
	progress.statusLabel.SetText("Creating debug bundle with collected logs...")

	request := &proto.DebugBundleRequest{
		Anonymize:  params.anonymize,
		SystemInfo: params.systemInfo,
	}

	if params.upload {
		request.UploadURL = params.uploadURL
	}

	resp, err := conn.DebugBundle(s.ctx, request)
	if err != nil {
		return fmt.Errorf("create debug bundle: %v", err)
	}

	// Show appropriate dialog based on upload status
	localPath := resp.GetPath()
	uploadFailureReason := resp.GetUploadFailureReason()
	uploadedKey := resp.GetUploadedKey()

	if params.upload {
		if uploadFailureReason != "" {
			showUploadFailedDialog(progress.window, localPath, uploadFailureReason)
		} else {
			showUploadSuccessDialog(s.app, progress.window, localPath, uploadedKey)
		}
	} else {
		showBundleCreatedDialog(progress.window, localPath)
	}

	enableUIControls(progress.uiControls)
	return nil
}

// Restore service to original state
func (s *serviceClient) restoreServiceState(conn proto.DaemonServiceClient, state *debugInitialState) {
	if state.wasDown {
		if _, err := conn.Down(s.ctx, &proto.DownRequest{}); err != nil {
			log.Errorf("Failed to restore down state: %v", err)
		} else {
			log.Info("Service state restored to down")
		}
	}

	if !state.isLevelTrace {
		if _, err := conn.SetLogLevel(s.ctx, &proto.SetLogLevelRequest{Level: state.logLevel}); err != nil {
			log.Errorf("Failed to restore log level: %v", err)
		} else {
			log.Info("Log level restored to original setting")
		}
	}
}

// Handle errors during debug collection
func handleError(progress *progressUI, errMsg string) {
	log.Errorf("%s", errMsg)
	progress.statusLabel.SetText(errMsg)
	progress.progressBar.Hide()
	enableUIControls(progress.uiControls)
}

func (s *serviceClient) handleDebugCreation(
	anonymize bool,
	systemInfo bool,
	upload bool,
	uploadURL string,
	statusLabel *widget.Label,
	uiControls []fyne.Disableable,
	w fyne.Window,
) {
	log.Infof("Creating debug bundle (Anonymized: %v, System Info: %v, Upload Attempt: %v)...",
		anonymize, systemInfo, upload)

	resp, err := s.createDebugBundle(anonymize, systemInfo, uploadURL)
	if err != nil {
		log.Errorf("Failed to create debug bundle: %v", err)
		statusLabel.SetText(fmt.Sprintf("Error creating bundle: %v", err))
		enableUIControls(uiControls)
		return
	}

	localPath := resp.GetPath()
	uploadFailureReason := resp.GetUploadFailureReason()
	uploadedKey := resp.GetUploadedKey()

	if upload {
		if uploadFailureReason != "" {
			showUploadFailedDialog(w, localPath, uploadFailureReason)
		} else {
			showUploadSuccessDialog(s.app, w, localPath, uploadedKey)
		}
	} else {
		showBundleCreatedDialog(w, localPath)
	}

	enableUIControls(uiControls)
	statusLabel.SetText("Bundle created successfully")
}

func (s *serviceClient) createDebugBundle(anonymize bool, systemInfo bool, uploadURL string) (*proto.DebugBundleResponse, error) {
	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		return nil, fmt.Errorf("get client: %v", err)
	}

	request := &proto.DebugBundleRequest{
		Anonymize:  anonymize,
		SystemInfo: systemInfo,
	}

	if uploadURL != "" {
		request.UploadURL = uploadURL
	}

	resp, err := conn.DebugBundle(s.ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to create debug bundle via daemon: %v", err)
	}

	return resp, nil
}

// formatDuration formats a duration in HH:MM:SS format
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d %= time.Hour
	m := d / time.Minute
	d %= time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

// createButtonWithAction creates a button with the given label and action
func createButtonWithAction(label string, action func()) *widget.Button {
	button := widget.NewButton(label, action)
	return button
}

// showUploadFailedDialog displays a dialog when upload fails
func showUploadFailedDialog(w fyne.Window, localPath, failureReason string) {
	content := container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Bundle upload failed:\n%s\n\n"+
			"A local copy was saved at:\n%s", failureReason, localPath)),
	)

	customDialog := dialog.NewCustom("Upload Failed", "Cancel", content, w)

	buttonBox := container.NewHBox(
		createButtonWithAction("Open file", func() {
			log.Infof("Attempting to open local file: %s", localPath)
			if openErr := open.Start(localPath); openErr != nil {
				log.Errorf("Failed to open local file '%s': %v", localPath, openErr)
				dialog.ShowError(fmt.Errorf("open the local file:\n%s\n\nError: %v", localPath, openErr), w)
			}
		}),
		createButtonWithAction("Open folder", func() {
			folderPath := filepath.Dir(localPath)
			log.Infof("Attempting to open local folder: %s", folderPath)
			if openErr := open.Start(folderPath); openErr != nil {
				log.Errorf("Failed to open local folder '%s': %v", folderPath, openErr)
				dialog.ShowError(fmt.Errorf("open the local folder:\n%s\n\nError: %v", folderPath, openErr), w)
			}
		}),
	)

	content.Add(buttonBox)
	customDialog.Show()
}

// showUploadSuccessDialog displays a dialog when upload succeeds
func showUploadSuccessDialog(a fyne.App, w fyne.Window, localPath, uploadedKey string) {
	log.Infof("Upload key: %s", uploadedKey)
	keyEntry := widget.NewEntry()
	keyEntry.SetText(uploadedKey)
	keyEntry.Disable()

	content := container.NewVBox(
		widget.NewLabel("Bundle uploaded successfully!"),
		widget.NewLabel(""),
		widget.NewLabel("Upload key:"),
		keyEntry,
		widget.NewLabel(""),
		widget.NewLabel(fmt.Sprintf("Local copy saved at:\n%s", localPath)),
	)

	customDialog := dialog.NewCustom("Upload Successful", "OK", content, w)

	copyBtn := createButtonWithAction("Copy key", func() {
		a.Clipboard().SetContent(uploadedKey)
		log.Info("Upload key copied to clipboard")
	})

	buttonBox := createButtonBox(localPath, w, copyBtn)
	content.Add(buttonBox)
	customDialog.Show()
}

// showBundleCreatedDialog displays a dialog when bundle is created without upload
func showBundleCreatedDialog(w fyne.Window, localPath string) {
	content := container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Bundle created locally at:\n%s\n\n"+
			"Administrator privileges may be required to access the file.", localPath)),
	)

	customDialog := dialog.NewCustom("Debug Bundle Created", "Cancel", content, w)

	buttonBox := createButtonBox(localPath, w, nil)
	content.Add(buttonBox)
	customDialog.Show()
}

func createButtonBox(localPath string, w fyne.Window, elems ...fyne.Widget) *fyne.Container {
	box := container.NewHBox()
	for _, elem := range elems {
		box.Add(elem)
	}

	fileBtn := createButtonWithAction("Open file", func() {
		log.Infof("Attempting to open local file: %s", localPath)
		if openErr := open.Start(localPath); openErr != nil {
			log.Errorf("Failed to open local file '%s': %v", localPath, openErr)
			dialog.ShowError(fmt.Errorf("open the local file:\n%s\n\nError: %v", localPath, openErr), w)
		}
	})

	folderBtn := createButtonWithAction("Open folder", func() {
		folderPath := filepath.Dir(localPath)
		log.Infof("Attempting to open local folder: %s", folderPath)
		if openErr := open.Start(folderPath); openErr != nil {
			log.Errorf("Failed to open local folder '%s': %v", folderPath, openErr)
			dialog.ShowError(fmt.Errorf("open the local folder:\n%s\n\nError: %v", folderPath, openErr), w)
		}
	})

	box.Add(fileBtn)
	box.Add(folderBtn)

	return box
}
