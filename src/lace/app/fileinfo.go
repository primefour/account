package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"
	"image/jpeg"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	//"github.com/disintegration/imaging"
	"github.com/rwcarlsen/goexif/exif"
	//_ "golang.org/x/image/bmp"

	"lace/mlog"
	"lace/model"
	"lace/utils"
)

const (
	/*
	  EXIF Image Orientations
	  1        2       3      4         5            6           7          8

	  888888  888888      88  88      8888888888  88                  88  8888888888
	  88          88      88  88      88  88      88  88          88  88      88  88
	  8888      8888    8888  8888    88          8888888888  8888888888          88
	  88          88      88  88
	  88          88  888888  888888
	*/
	Upright            = 1
	UprightMirrored    = 2
	UpsideDown         = 3
	UpsideDownMirrored = 4
	RotatedCWMirrored  = 5
	RotatedCCW         = 6
	RotatedCCWMirrored = 7
	RotatedCW          = 8

	MaxImageSize                 = 6048 * 4032 // 24 megapixels, roughly 36MB as a raw image
	IMAGE_THUMBNAIL_PIXEL_WIDTH  = 120
	IMAGE_THUMBNAIL_PIXEL_HEIGHT = 100
	IMAGE_PREVIEW_PIXEL_WIDTH    = 1920
)

func (a *App) FileBackend() (utils.FileBackend, *model.AppError) {
	return utils.NewFileBackend(a.Config().FileSettings, true)
}

func (a *App) ReadFile(path string) ([]byte, *model.AppError) {
	backend, err := a.FileBackend()
	if err != nil {
		return nil, err
	}
	return backend.ReadFile(path)
}

// Caller must close the first return value
func (a *App) FileReader(path string) (io.ReadCloser, *model.AppError) {
	backend, err := a.FileBackend()
	if err != nil {
		return nil, err
	}
	return backend.Reader(path)
}

func (a *App) FileExists(path string) (bool, *model.AppError) {
	backend, err := a.FileBackend()
	if err != nil {
		return false, err
	}
	return backend.FileExists(path)
}

func (a *App) MoveFile(oldPath, newPath string) *model.AppError {
	backend, err := a.FileBackend()
	if err != nil {
		return err
	}
	return backend.MoveFile(oldPath, newPath)
}

func (a *App) WriteFile(fr io.Reader, path string) (int64, *model.AppError) {
	backend, err := a.FileBackend()
	if err != nil {
		return 0, err
	}

	return backend.WriteFile(fr, path)
}

func (a *App) RemoveFile(path string) *model.AppError {
	backend, err := a.FileBackend()
	if err != nil {
		return err
	}
	return backend.RemoveFile(path)
}

func (a *App) GetInfoForFilename(filename string) *model.FileInfo {
	return nil
}

func (a *App) GeneratePublicLink(siteURL string, info *model.FileInfo) string {
	hash := GeneratePublicLinkHash(info.Id, *a.Config().FileSettings.PublicLinkSalt)
	return fmt.Sprintf("%s/files/%v/public?h=%s", siteURL, info.Id, hash)
}

func GeneratePublicLinkHash(fileId, salt string) string {
	hash := sha256.New()
	hash.Write([]byte(salt))
	hash.Write([]byte(fileId))

	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func (a *App) UploadMultipartFiles(teamId string, channelId string, userId string, fileHeaders []*multipart.FileHeader, clientIds []string, now time.Time) (*model.FileUploadResponse, *model.AppError) {
	files := make([]io.ReadCloser, len(fileHeaders))
	filenames := make([]string, len(fileHeaders))

	for i, fileHeader := range fileHeaders {
		file, fileErr := fileHeader.Open()
		if fileErr != nil {
			return nil, model.NewAppError("UploadFiles", "api.file.upload_file.bad_parse.app_error", nil, fileErr.Error(), http.StatusBadRequest)
		}

		// Will be closed after UploadFiles returns
		defer file.Close()

		files[i] = file
		filenames[i] = fileHeader.Filename
	}

	return a.UploadFiles(teamId, channelId, userId, files, filenames, clientIds, now)
}

// Uploads some files to the given team and channel as the given user. files and filenames should have
// the same length. clientIds should either not be provided or have the same length as files and filenames.
// The provided files should be closed by the caller so that they are not leaked.
func (a *App) UploadFiles(teamId string, channelId string, userId string, files []io.ReadCloser, filenames []string, clientIds []string, now time.Time) (*model.FileUploadResponse, *model.AppError) {
	if len(*a.Config().FileSettings.DriverName) == 0 {
		return nil, model.NewAppError("uploadFile", "api.file.upload_file.storage.app_error", nil, "", http.StatusNotImplemented)
	}

	if len(filenames) != len(files) || (len(clientIds) > 0 && len(clientIds) != len(files)) {
		return nil, model.NewAppError("UploadFiles", "api.file.upload_file.incorrect_number_of_files.app_error", nil, "", http.StatusBadRequest)
	}

	resStruct := &model.FileUploadResponse{
		FileInfos: []*model.FileInfo{},
		ClientIds: []string{},
	}

	previewPathList := []string{}
	thumbnailPathList := []string{}
	imageDataList := [][]byte{}

	for i, file := range files {
		buf := bytes.NewBuffer(nil)
		io.Copy(buf, file)
		data := buf.Bytes()

		info, data, err := a.DoUploadFileExpectModification(now, teamId, channelId, userId, filenames[i], data)
		if err != nil {
			return nil, err
		}

		if info.PreviewPath != "" || info.ThumbnailPath != "" {
			previewPathList = append(previewPathList, info.PreviewPath)
			thumbnailPathList = append(thumbnailPathList, info.ThumbnailPath)
			imageDataList = append(imageDataList, data)
		}

		resStruct.FileInfos = append(resStruct.FileInfos, info)

		if len(clientIds) > 0 {
			resStruct.ClientIds = append(resStruct.ClientIds, clientIds[i])
		}
	}

	a.HandleImages(previewPathList, thumbnailPathList, imageDataList)

	return resStruct, nil
}

func (a *App) DoUploadFile(now time.Time, rawTeamId string, rawChannelId string, rawUserId string, rawFilename string, data []byte) (*model.FileInfo, *model.AppError) {
	info, _, err := a.DoUploadFileExpectModification(now, rawTeamId, rawChannelId, rawUserId, rawFilename, data)
	return info, err
}

func (a *App) DoUploadFileExpectModification(now time.Time, rawTeamId string, rawChannelId string, rawUserId string, rawFilename string, data []byte) (*model.FileInfo, []byte, *model.AppError) {
	filename := filepath.Base(rawFilename)
	teamId := filepath.Base(rawTeamId)
	channelId := filepath.Base(rawChannelId)
	userId := filepath.Base(rawUserId)

	info, err := model.GetInfoForBytes(filename, data)
	if err != nil {
		err.StatusCode = http.StatusBadRequest
		return nil, data, err
	}

	if orientation, err := getImageOrientation(bytes.NewReader(data)); err == nil &&
		(orientation == RotatedCWMirrored ||
			orientation == RotatedCCW ||
			orientation == RotatedCCWMirrored ||
			orientation == RotatedCW) {
		info.Width, info.Height = info.Height, info.Width
	}

	info.Id = model.NewId()
	info.CreatorId = userId
	info.CreateAt = now.UnixNano() / int64(time.Millisecond)

	pathPrefix := now.Format("20060102") + "/teams/" + teamId + "/channels/" + channelId + "/users/" + userId + "/" + info.Id + "/"
	info.Path = pathPrefix + filename

	if info.IsImage() {
		// Check dimensions before loading the whole thing into memory later on
		if info.Width*info.Height > MaxImageSize {
			err := model.NewAppError("uploadFile", "api.file.upload_file.large_image.app_error", map[string]interface{}{"Filename": filename}, "", http.StatusBadRequest)
			return nil, data, err
		}

		nameWithoutExtension := filename[:strings.LastIndex(filename, ".")]
		info.PreviewPath = pathPrefix + nameWithoutExtension + "_preview.jpg"
		info.ThumbnailPath = pathPrefix + nameWithoutExtension + "_thumb.jpg"
	}

	if _, err := a.WriteFile(bytes.NewReader(data), info.Path); err != nil {
		return nil, data, err
	}

	if result := <-a.FileInfoProvider().Save(info); result.Err != nil {
		return nil, data, result.Err
	}

	return info, data, nil
}

func (a *App) HandleImages(previewPathList []string, thumbnailPathList []string, fileData [][]byte) {
	wg := new(sync.WaitGroup)

	for i := range fileData {
		img, width, height := prepareImage(fileData[i])
		if img != nil {
			wg.Add(2)
			go func(img *image.Image, path string, width int, height int) {
				defer wg.Done()
				a.generateThumbnailImage(*img, path, width, height)
			}(img, thumbnailPathList[i], width, height)

			go func(img *image.Image, path string, width int) {
				defer wg.Done()
				a.generatePreviewImage(*img, path, width)
			}(img, previewPathList[i], width)
		}
	}
	wg.Wait()
}

func prepareImage(fileData []byte) (*image.Image, int, int) {
	// Decode image bytes into Image object
	img, imgType, err := image.Decode(bytes.NewReader(fileData))
	if err != nil {
		mlog.Error(fmt.Sprintf("Unable to decode image err=%v", err))
		return nil, 0, 0
	}

	width := img.Bounds().Dx()
	height := img.Bounds().Dy()

	// Fill in the background of a potentially-transparent png file as white
	if imgType == "png" {
		dst := image.NewRGBA(img.Bounds())
		draw.Draw(dst, dst.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
		draw.Draw(dst, dst.Bounds(), img, img.Bounds().Min, draw.Over)
		img = dst
	}

	// Flip the image to be upright
	orientation, _ := getImageOrientation(bytes.NewReader(fileData))
	img = makeImageUpright(img, orientation)

	return &img, width, height
}

func makeImageUpright(img image.Image, orientation int) image.Image {
	/*
		switch orientation {
		case UprightMirrored:
			return imaging.FlipH(img)
		case UpsideDown:
			return imaging.Rotate180(img)
		case UpsideDownMirrored:
			return imaging.FlipV(img)
		case RotatedCWMirrored:
			return imaging.Transpose(img)
		case RotatedCCW:
			return imaging.Rotate270(img)
		case RotatedCCWMirrored:
			return imaging.Transverse(img)
		case RotatedCW:
			return imaging.Rotate90(img)
		default:
			return img
		}
	*/
	return img
}

func getImageOrientation(input io.Reader) (int, error) {
	if exifData, err := exif.Decode(input); err != nil {
		return Upright, err
	} else {
		if tag, err := exifData.Get("Orientation"); err != nil {
			return Upright, err
		} else {
			orientation, err := tag.Int(0)
			if err != nil {
				return Upright, err
			} else {
				return orientation, nil
			}
		}
	}
}

func (a *App) generateThumbnailImage(img image.Image, thumbnailPath string, width int, height int) {
	thumbWidth := float64(IMAGE_THUMBNAIL_PIXEL_WIDTH)
	thumbHeight := float64(IMAGE_THUMBNAIL_PIXEL_HEIGHT)
	imgWidth := float64(width)
	imgHeight := float64(height)

	var thumbnail image.Image
	if imgHeight < IMAGE_THUMBNAIL_PIXEL_HEIGHT && imgWidth < thumbWidth {
		thumbnail = img
	} else if imgHeight/imgWidth < thumbHeight/thumbWidth {
		//thumbnail = imaging.Resize(img, 0, IMAGE_THUMBNAIL_PIXEL_HEIGHT, imaging.Lanczos)
	} else {
		//thumbnail = imaging.Resize(img, IMAGE_THUMBNAIL_PIXEL_WIDTH, 0, imaging.Lanczos)
	}

	buf := new(bytes.Buffer)
	if err := jpeg.Encode(buf, thumbnail, &jpeg.Options{Quality: 90}); err != nil {
		mlog.Error(fmt.Sprintf("Unable to encode image as jpeg path=%v err=%v", thumbnailPath, err))
		return
	}

	if _, err := a.WriteFile(buf, thumbnailPath); err != nil {
		mlog.Error(fmt.Sprintf("Unable to upload thumbnail path=%v err=%v", thumbnailPath, err))
		return
	}
}

func (a *App) generatePreviewImage(img image.Image, previewPath string, width int) {
	var preview image.Image

	if width > IMAGE_PREVIEW_PIXEL_WIDTH {
		//preview = imaging.Resize(img, IMAGE_PREVIEW_PIXEL_WIDTH, 0, imaging.Lanczos)
	} else {
		preview = img
	}

	buf := new(bytes.Buffer)

	if err := jpeg.Encode(buf, preview, &jpeg.Options{Quality: 90}); err != nil {
		mlog.Error(fmt.Sprintf("Unable to encode image as preview jpg err=%v", err), mlog.String("path", previewPath))
		return
	}

	if _, err := a.WriteFile(buf, previewPath); err != nil {
		mlog.Error(fmt.Sprintf("Unable to upload preview err=%v", err), mlog.String("path", previewPath))
		return
	}
}

func (a *App) GetFileInfo(fileId string) (*model.FileInfo, *model.AppError) {
	if result := <-a.FileInfoProvider().Get(fileId); result.Err != nil {
		return nil, result.Err
	} else {
		return result.Data.(*model.FileInfo), nil
	}
}

func (a *App) CopyFileInfos(userId string, fileIds []string) ([]string, *model.AppError) {
	newFileIds := []string{}

	now := model.GetMillis()

	for _, fileId := range fileIds {
		fileInfo := &model.FileInfo{}

		if result := <-a.FileInfoProvider().Get(fileId); result.Err != nil {
			return nil, result.Err
		} else {
			fileInfo = result.Data.(*model.FileInfo)
		}

		fileInfo.Id = model.NewId()
		fileInfo.CreatorId = userId
		fileInfo.CreateAt = now
		fileInfo.UpdateAt = now

		if result := <-a.FileInfoProvider().Save(fileInfo); result.Err != nil {
			return newFileIds, result.Err
		}

		newFileIds = append(newFileIds, fileInfo.Id)
	}

	return newFileIds, nil
}
