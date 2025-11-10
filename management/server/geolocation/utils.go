package geolocation

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// decompressTarGzFile decompresses a .tar.gz file.
// Security: Validates file paths to prevent path traversal attacks and ensures files are closed properly.
func decompressTarGzFile(filepath, destDir string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	// Security: Limit extraction size to prevent DoS attacks
	const maxExtractSize = 100 * 1024 * 1024 // 100MB
	var totalExtracted int64

	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		if header.Typeflag == tar.TypeReg {
			// Security: Validate file name to prevent path traversal
			fileName := path.Base(header.Name)
			if fileName == "" || fileName == "." || fileName == ".." {
				continue // Skip invalid file names
			}
			
			// Security: Validate file size to prevent DoS
			if header.Size < 0 || header.Size > maxExtractSize {
				return fmt.Errorf("file size %d exceeds maximum allowed size %d", header.Size, maxExtractSize)
			}
			
			// Security: Check total extracted size
			if totalExtracted+header.Size > maxExtractSize {
				return fmt.Errorf("total extraction size would exceed maximum allowed size %d", maxExtractSize)
			}

			outFilePath := path.Join(destDir, fileName)
			
			// Security: Validate resolved path is within destination directory
			absDestDir, err := path.Abs(destDir)
			if err != nil {
				return fmt.Errorf("failed to resolve destination directory: %w", err)
			}
			absOutPath, err := path.Abs(outFilePath)
			if err != nil {
				return fmt.Errorf("failed to resolve output path: %w", err)
			}
			if !strings.HasPrefix(absOutPath, absDestDir) {
				return fmt.Errorf("path traversal attempt detected: %s", header.Name)
			}

			outFile, err := os.Create(outFilePath)
			if err != nil {
				return err
			}

			// Security: Use LimitReader to prevent extraction of files larger than header.Size
			limitedReader := io.LimitReader(tarReader, header.Size)
			written, err := io.Copy(outFile, limitedReader)
			
			// Security: Always close the file, even on error
			closeErr := outFile.Close()
			if err != nil {
				// Remove partially written file on error
				_ = os.Remove(outFilePath)
				return err
			}
			if closeErr != nil {
				return fmt.Errorf("failed to close output file: %w", closeErr)
			}
			
			totalExtracted += written
		}
	}

	return nil
}

// decompressZipFile decompresses a .zip file.
// Security: Validates file paths to prevent path traversal attacks and ensures files are closed properly.
func decompressZipFile(filepath, destDir string) error {
	r, err := zip.OpenReader(filepath)
	if err != nil {
		return err
	}
	defer r.Close()

	// Security: Limit extraction size to prevent DoS attacks
	const maxExtractSize = 100 * 1024 * 1024 // 100MB
	var totalExtracted int64

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		// Security: Validate file name to prevent path traversal
		fileName := path.Base(f.Name)
		if fileName == "" || fileName == "." || fileName == ".." {
			continue // Skip invalid file names
		}
		
		// Security: Validate file size to prevent DoS
		if f.UncompressedSize64 > maxExtractSize {
			return fmt.Errorf("file size %d exceeds maximum allowed size %d", f.UncompressedSize64, maxExtractSize)
		}
		
		// Security: Check total extracted size
		if totalExtracted+int64(f.UncompressedSize64) > maxExtractSize {
			return fmt.Errorf("total extraction size would exceed maximum allowed size %d", maxExtractSize)
		}

		outFilePath := path.Join(destDir, fileName)
		
		// Security: Validate resolved path is within destination directory
		absDestDir, err := path.Abs(destDir)
		if err != nil {
			return fmt.Errorf("failed to resolve destination directory: %w", err)
		}
		absOutPath, err := path.Abs(outFilePath)
		if err != nil {
			return fmt.Errorf("failed to resolve output path: %w", err)
		}
		if !strings.HasPrefix(absOutPath, absDestDir) {
			return fmt.Errorf("path traversal attempt detected: %s", f.Name)
		}

		outFile, err := os.Create(outFilePath)
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			// Security: Close file on error
			_ = outFile.Close()
			_ = os.Remove(outFilePath)
			return err
		}

		// Security: Use LimitReader to prevent extraction of files larger than UncompressedSize64
		limitedReader := io.LimitReader(rc, int64(f.UncompressedSize64))
		written, err := io.Copy(outFile, limitedReader)
		
		// Security: Always close resources, even on error
		closeErr1 := outFile.Close()
		closeErr2 := rc.Close()
		
		if err != nil {
			// Remove partially written file on error
			_ = os.Remove(outFilePath)
			return err
		}
		if closeErr1 != nil {
			return fmt.Errorf("failed to close output file: %w", closeErr1)
		}
		if closeErr2 != nil {
			return fmt.Errorf("failed to close zip file reader: %w", closeErr2)
		}
		
		totalExtracted += written
	}

	return nil
}

// calculateFileSHA256 calculates the SHA256 checksum of a file.
func calculateFileSHA256(filepath string) ([]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// loadChecksumFromFile loads the first checksum from a file.
func loadChecksumFromFile(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) > 0 {
			return parts[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", nil
}

// verifyChecksum compares the calculated SHA256 checksum of a file against the expected checksum.
func verifyChecksum(filepath, expectedChecksum string) error {
	calculatedChecksum, err := calculateFileSHA256(filepath)

	fileCheckSum := fmt.Sprintf("%x", calculatedChecksum)
	if err != nil {
		return err
	}

	if fileCheckSum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, fileCheckSum)
	}

	return nil
}

// downloadFile downloads a file from a URL and saves it to a local file path.
// Security: Uses HTTP client with timeout and limits response body size to prevent DoS attacks.
func downloadFile(url, filepath string) error {
	// Security: Use HTTP client with timeout to prevent hanging requests
	client := &http.Client{
		Timeout: 30 * time.Second, // 30 second timeout for file downloads
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Security: Limit response body size to prevent DoS attacks
	// 100MB is a reasonable limit for geolocation database files
	const maxDownloadSize = 100 * 1024 * 1024 // 100MB
	limitedReader := io.LimitReader(resp.Body, maxDownloadSize+1)
	
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return err
	}

	// Security: Check if body exceeded size limit
	if len(bodyBytes) > maxDownloadSize {
		return fmt.Errorf("downloaded file size exceeds maximum allowed size %d bytes", maxDownloadSize)
	}

	if resp.StatusCode != http.StatusOK {
		// Security: Limit error message length to prevent information leakage
		errorMsg := string(bodyBytes)
		if len(errorMsg) > 200 {
			errorMsg = errorMsg[:200] + "..."
		}
		return fmt.Errorf("unexpected error occurred while downloading the file (status %d): %s", resp.StatusCode, errorMsg)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); closeErr != nil {
			// Log error but don't fail the operation if file was written successfully
			_ = closeErr
		}
	}()

	_, err = io.Copy(out, bytes.NewBuffer(bodyBytes))
	return err
}

// getFilenameFromURL extracts the filename from the Content-Disposition header of an HTTP response.
// Security: Validates header array bounds and filename to prevent panics and path traversal.
func getFilenameFromURL(url string) (string, error) {
	// Security: Use HTTP client with timeout to prevent hanging requests
	client := &http.Client{
		Timeout: 10 * time.Second, // 10 second timeout for HEAD requests
	}
	resp, err := client.Head(url)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	// Security: Validate Content-Disposition header exists and has elements
	contentDisposition := resp.Header["Content-Disposition"]
	if len(contentDisposition) == 0 {
		return "", fmt.Errorf("Content-Disposition header not found")
	}

	_, params, err := mime.ParseMediaType(contentDisposition[0])
	if err != nil {
		return "", fmt.Errorf("failed to parse Content-Disposition header: %w", err)
	}

	filename := params["filename"]
	
	// Security: Validate filename to prevent path traversal
	if filename == "" {
		return "", fmt.Errorf("filename not found in Content-Disposition header")
	}
	
	// Security: Extract only the base name to prevent path traversal
	filename = path.Base(filename)
	if filename == "" || filename == "." || filename == ".." {
		return "", fmt.Errorf("invalid filename in Content-Disposition header: %s", params["filename"])
	}

	return filename, nil
}
