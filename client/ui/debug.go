//go:build !(linux && 386)

package main

import (
	"fmt"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open"

	"github.com/netbirdio/netbird/client/proto"
	nbstatus "github.com/netbirdio/netbird/client/status"
	uptypes "github.com/netbirdio/netbird/upload-server/types"
)

func (s *serviceClient) showDebugUI() {
	w := s.app.NewWindow("NetBird Debug")
	w.Resize(fyne.NewSize(600, 400))
	w.SetFixedSize(true)

	anonymizeCheck := widget.NewCheck("Anonymize sensitive information (IPs, domains, ...)", nil)
	anonymizeCheck.SetChecked(true)
	systemInfoCheck := widget.NewCheck("Include system information", nil)
	systemInfoCheck.SetChecked(true)
	uploadCheck := widget.NewCheck("Upload bundle automatically after creation", nil)
	uploadCheck.SetChecked(true)

	uploadURLLabel := widget.NewLabel("Debug Upload URL:")
	uploadURL := widget.NewEntry()
	uploadURL.SetText(uptypes.DefaultBundleURL)
	uploadURL.SetPlaceHolder("Enter upload URL")

	statusLabel := widget.NewLabel("")
	statusLabel.Hide()

	createButton := widget.NewButton("Create Debug Bundle", nil)

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

	createButton.OnTapped = s.getCreateHandler(createButton, statusLabel, uploadCheck, uploadURL, anonymizeCheck, systemInfoCheck, w)

	content := container.NewVBox(
		widget.NewLabel("Create a debug bundle to help troubleshoot issues with NetBird"),
		widget.NewLabel(""),
		anonymizeCheck,
		systemInfoCheck,
		uploadCheck,
		uploadURLContainer,
		widget.NewLabel(""),
		statusLabel,
		createButton,
	)

	paddedContent := container.NewPadded(content)
	w.SetContent(paddedContent)

	w.Show()
}

func (s *serviceClient) getCreateHandler(
	createButton *widget.Button,
	statusLabel *widget.Label,
	uploadCheck *widget.Check,
	uploadURL *widget.Entry,
	anonymizeCheck *widget.Check,
	systemInfoCheck *widget.Check,
	w fyne.Window,
) func() {
	return func() {
		createButton.Disable()
		statusLabel.SetText("Creating debug bundle...")
		statusLabel.Show()

		var uploadUrl string
		if uploadCheck.Checked {
			uploadUrl = uploadURL.Text

			if uploadUrl == "" {
				statusLabel.SetText("Error: Upload URL is required when upload is enabled")
				createButton.Enable()
				return
			}
		}

		go s.handleDebugCreation(anonymizeCheck.Checked, systemInfoCheck.Checked, uploadCheck.Checked, uploadUrl, statusLabel, createButton, w)
	}
}

func (s *serviceClient) handleDebugCreation(
	anonymize bool,
	systemInfo bool,
	upload bool,
	uploadUrl string,
	statusLabel *widget.Label,
	createButton *widget.Button,
	w fyne.Window,
) {
	log.Infof("Creating debug bundle (Anonymized: %v, System Info: %v, Upload Attempt: %v)...",
		anonymize, systemInfo, upload)

	resp, err := s.createDebugBundle(anonymize, systemInfo, uploadUrl)
	if err != nil {
		log.Errorf("Failed to create debug bundle: %v", err)
		statusLabel.SetText(fmt.Sprintf("Error creating bundle: %v", err))
		createButton.Enable()
		return
	}

	localPath := resp.GetPath()
	uploadFailureReason := resp.GetUploadFailureReason()
	uploadedKey := resp.GetUploadedKey()

	if upload {
		if uploadFailureReason != "" {
			showUploadFailedDialog(w, localPath, uploadFailureReason)
		} else {
			showUploadSuccessDialog(w, localPath, uploadedKey)
		}
	} else {
		showBundleCreatedDialog(w, localPath)
	}

	createButton.Enable()
	statusLabel.SetText("Bundle created successfully")
}

func (s *serviceClient) createDebugBundle(anonymize bool, systemInfo bool, uploadURL string) (*proto.DebugBundleResponse, error) {
	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		return nil, fmt.Errorf("get client: %v", err)
	}

	statusResp, err := conn.Status(s.ctx, &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil {
		log.Warnf("failed to get status for debug bundle: %v", err)
	}

	var statusOutput string
	if statusResp != nil {
		overview := nbstatus.ConvertToStatusOutputOverview(statusResp, anonymize, "", nil, nil, nil)
		statusOutput = nbstatus.ParseToFullDetailSummary(overview)
	}

	request := &proto.DebugBundleRequest{
		Anonymize:  anonymize,
		Status:     statusOutput,
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

// showUploadFailedDialog displays a dialog when upload fails
func showUploadFailedDialog(parent fyne.Window, localPath, failureReason string) {
	content := container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Bundle upload failed:\n%s\n\n"+
			"A local copy was saved at:\n%s", failureReason, localPath)),
	)

	customDialog := dialog.NewCustom("Upload Failed", "Cancel", content, parent)

	buttonBox := container.NewHBox(
		widget.NewButton("Open File", func() {
			log.Infof("Attempting to open local file: %s", localPath)
			if openErr := open.Start(localPath); openErr != nil {
				log.Errorf("Failed to open local file '%s': %v", localPath, openErr)
				dialog.ShowError(fmt.Errorf("Failed to open the local file:\n%s\n\nError: %v", localPath, openErr), parent)
			}
			customDialog.Hide()
		}),
		widget.NewButton("Open Folder", func() {
			folderPath := filepath.Dir(localPath)
			log.Infof("Attempting to open local folder: %s", folderPath)
			if openErr := open.Start(folderPath); openErr != nil {
				log.Errorf("Failed to open local folder '%s': %v", folderPath, openErr)
				dialog.ShowError(fmt.Errorf("Failed to open the local folder:\n%s\n\nError: %v", folderPath, openErr), parent)
			}
			customDialog.Hide()
		}),
	)

	content.Add(buttonBox)
	customDialog.Show()
}

// showUploadSuccessDialog displays a dialog when upload succeeds
func showUploadSuccessDialog(parent fyne.Window, localPath, uploadedKey string) {
	keyEntry := widget.NewEntry()
	keyEntry.SetText(uploadedKey)
	keyEntry.Disable()

	content := container.NewVBox(
		widget.NewLabel("Bundle uploaded successfully!"),
		widget.NewLabel(""),
		widget.NewLabel("Upload Key:"),
		keyEntry,
		widget.NewLabel(""),
		widget.NewLabel(fmt.Sprintf("Local copy saved at:\n%s", localPath)),
	)

	customDialog := dialog.NewCustom("Upload Successful", "OK", content, parent)

	buttonBox := container.NewHBox(
		widget.NewButton("Copy Key", func() {
			parent.Clipboard().SetContent(uploadedKey)
			log.Info("Upload key copied to clipboard")
		}),
		widget.NewButton("Open Local Folder", func() {
			folderPath := filepath.Dir(localPath)
			log.Infof("Attempting to open local folder: %s", folderPath)
			if openErr := open.Start(folderPath); openErr != nil {
				log.Errorf("Failed to open local folder '%s': %v", folderPath, openErr)
				dialog.ShowError(fmt.Errorf("Failed to open the local folder:\n%s\n\nError: %v", folderPath, openErr), parent)
			}
		}),
	)

	content.Add(buttonBox)
	customDialog.Show()
}

// showBundleCreatedDialog displays a dialog when bundle is created without upload
func showBundleCreatedDialog(parent fyne.Window, localPath string) {
	content := container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Bundle created locally at:\n%s\n\n"+
			"Administrator privileges may be required depending on location.", localPath)),
	)

	customDialog := dialog.NewCustom("Debug Bundle Created", "Cancel", content, parent)

	buttonBox := container.NewHBox(
		widget.NewButton("Open File", func() {
			log.Infof("Attempting to open local file: %s", localPath)
			if openErr := open.Start(localPath); openErr != nil {
				log.Errorf("Failed to open local file '%s': %v", localPath, openErr)
				dialog.ShowError(fmt.Errorf("Failed to open the local file:\n%s\n\nError: %v", localPath, openErr), parent)
			}
			customDialog.Hide()
		}),
		widget.NewButton("Open Folder", func() {
			folderPath := filepath.Dir(localPath)
			log.Infof("Attempting to open local folder: %s", folderPath)
			if openErr := open.Start(folderPath); openErr != nil {
				log.Errorf("Failed to open local folder '%s': %v", folderPath, openErr)
				dialog.ShowError(fmt.Errorf("Failed to open the local folder:\n%s\n\nError: %v", folderPath, openErr), parent)
			}
			customDialog.Hide()
		}),
	)

	content.Add(buttonBox)
	customDialog.Show()
}
