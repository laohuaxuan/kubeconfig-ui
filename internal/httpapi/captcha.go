package httpapi

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/rand"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var captchaStore = make(map[string]captchaData)

type captchaData struct {
	code      string
	expiresAt time.Time
}

const captchaChars = "0123456789"

var digitSegments = map[rune][7]bool{
	'0': {true, true, true, false, true, true, true},
	'1': {false, false, true, false, false, true, false},
	'2': {true, false, true, true, true, false, true},
	'3': {true, false, true, true, false, true, true},
	'4': {false, true, true, true, false, true, false},
	'5': {true, true, false, true, false, true, true},
	'6': {true, true, false, true, true, true, true},
	'7': {true, false, true, false, false, true, false},
	'8': {true, true, true, true, true, true, true},
	'9': {true, true, true, true, false, true, true},
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func generateCaptchaCode(length int) string {
	var sb strings.Builder
	for i := 0; i < length; i++ {
		sb.WriteByte(captchaChars[rand.Intn(len(captchaChars))])
	}
	return sb.String()
}

func generateCaptchaImage(code string) image.Image {
	const (
		width  = 120
		height = 32
	)

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	bgColor := color.RGBA{236, 248, 166, 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)

	borderColor := color.RGBA{102, 128, 52, 255}
	drawRect(img, 0, 0, width, 1, borderColor)
	drawRect(img, 0, height-1, width, 1, borderColor)
	drawRect(img, 0, 0, 1, height, borderColor)
	drawRect(img, width-1, 0, 1, height, borderColor)

	noiseColor := color.RGBA{154, 177, 93, 255}
	drawLine(img, 4, 6, width-5, 6, noiseColor)
	drawLine(img, 4, height-7, width-5, height-7, noiseColor)
	for i := 0; i < 8; i++ {
		x := 2 + rand.Intn(width-4)
		y := 2 + rand.Intn(height-4)
		img.Set(x, y, noiseColor)
	}

	chars := []rune(code)
	charWidth := width / len(chars)
	textColor := color.RGBA{45, 63, 20, 255}
	for i, ch := range chars {
		x := i*charWidth + 8
		y := 4
		drawDigit(img, ch, x, y, textColor)
	}

	return img
}

func drawRect(img *image.RGBA, x, y, w, h int, c color.RGBA) {
	if w <= 0 || h <= 0 {
		return
	}
	for yy := y; yy < y+h; yy++ {
		if yy < 0 || yy >= img.Bounds().Dy() {
			continue
		}
		for xx := x; xx < x+w; xx++ {
			if xx < 0 || xx >= img.Bounds().Dx() {
				continue
			}
			img.Set(xx, yy, c)
		}
	}
}

func drawLine(img *image.RGBA, x1, y1, x2, y2 int, c color.RGBA) {
	dx := abs(x2 - x1)
	dy := -abs(y2 - y1)
	sx := -1
	if x1 < x2 {
		sx = 1
	}
	sy := -1
	if y1 < y2 {
		sy = 1
	}
	err := dx + dy

	for {
		if x1 >= 0 && x1 < img.Bounds().Dx() && y1 >= 0 && y1 < img.Bounds().Dy() {
			img.Set(x1, y1, c)
		}
		if x1 == x2 && y1 == y2 {
			break
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x1 += sx
		}
		if e2 <= dx {
			err += dx
			y1 += sy
		}
	}
}

func drawDigit(img *image.RGBA, ch rune, x, y int, c color.RGBA) {
	segments, ok := digitSegments[ch]
	if !ok {
		return
	}

	const (
		thick  = 2
		segLen = 8
	)

	if segments[0] {
		drawRect(img, x+thick, y, segLen, thick, c)
	}
	if segments[1] {
		drawRect(img, x, y+thick, thick, segLen, c)
	}
	if segments[2] {
		drawRect(img, x+thick+segLen, y+thick, thick, segLen, c)
	}
	if segments[3] {
		drawRect(img, x+thick, y+thick+segLen, segLen, thick, c)
	}
	if segments[4] {
		drawRect(img, x, y+2*thick+segLen, thick, segLen, c)
	}
	if segments[5] {
		drawRect(img, x+thick+segLen, y+2*thick+segLen, thick, segLen, c)
	}
	if segments[6] {
		drawRect(img, x+thick, y+2*thick+2*segLen, segLen, thick, c)
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func (h *Handler) captchaImage(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		token = generateCaptchaCode(32)
	}

	code := generateCaptchaCode(4)
	captchaStore[token] = captchaData{
		code:      code,
		expiresAt: time.Now().Add(5 * time.Minute),
	}

	img := generateCaptchaImage(code)

	c.Header("Content-Type", "image/png")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
	c.Header("X-Captcha-Token", token)

	_ = png.Encode(c.Writer, img)
}

func (h *Handler) verifyCaptcha(token, code string) bool {
	data, ok := captchaStore[token]
	if !ok {
		return false
	}

	if time.Now().After(data.expiresAt) {
		delete(captchaStore, token)
		return false
	}

	if strings.EqualFold(data.code, code) {
		delete(captchaStore, token)
		return true
	}

	return false
}
