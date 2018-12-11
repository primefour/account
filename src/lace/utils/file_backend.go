package utils

import (
	"io"
	"lace/model"
	"net/http"
)

type FileBackend interface {
	TestConnection() *model.AppError

	Reader(path string) (io.ReadCloser, *model.AppError)
	ReadFile(path string) ([]byte, *model.AppError)
	FileExists(path string) (bool, *model.AppError)
	CopyFile(oldPath, newPath string) *model.AppError
	MoveFile(oldPath, newPath string) *model.AppError
	WriteFile(fr io.Reader, path string) (int64, *model.AppError)
	RemoveFile(path string) *model.AppError

	ListDirectory(path string) (*[]string, *model.AppError)
	RemoveDirectory(path string) *model.AppError
}

func NewFileBackend(settings *model.FileSettings, enableComplianceFeatures bool) (FileBackend, *model.AppError) {
	switch *settings.DriverName {
	case model.IMAGE_DRIVER_LOCAL:
		return &LocalFileBackend{
			directory: "./data",
		}, nil
	}
	return nil, model.NewAppError("NewFileBackend", "api.file.no_driver.app_error", nil, "", http.StatusInternalServerError)
}
