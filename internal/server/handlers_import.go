package server

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/brett6320/recipe-manager/internal/importer"
)

func (s *Server) handleImportPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "import.html", pageData{Title: "Import", Data: map[string]any{
		"Folder":  r.URL.Query().Get("folder"),
		"MaxMB":   s.cfg.ImportMaxSize >> 20,
		"Folders": nil,
	}})
}

// handleImport accepts a URL, an uploaded file (HTML/JSON/PDF/text) or
// pasted text, parses it and shows the result in the normal recipe editor
// so the user reviews everything before anything is stored.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.ImportMaxSize+64<<10)
	if err := r.ParseMultipartForm(s.cfg.ImportMaxSize); err != nil { //nolint:gosec // body already capped by MaxBytesReader above
		s.importError(w, r, "Upload too large or malformed (limit "+itoaMB(s.cfg.ImportMaxSize)+").")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	ipKey := "import:" + u.Username
	if s.failures.Locked(ipKey) {
		s.importError(w, r, "Too many failed imports; try again later.")
		return
	}

	var res *importer.Result
	var err error
	switch {
	case strings.TrimSpace(r.FormValue("url")) != "":
		res, err = s.fetcher.FromURL(r.Context(), r.FormValue("url"))
	case hasFile(r):
		f, hdr, ferr := r.FormFile("file")
		if ferr != nil {
			err = errors.New("could not read upload")
			break
		}
		data, rerr := io.ReadAll(io.LimitReader(f, s.cfg.ImportMaxSize+1))
		_ = f.Close()
		if rerr != nil || int64(len(data)) > s.cfg.ImportMaxSize {
			err = errors.New("file too large")
			break
		}
		res, err = importer.FromBytes(data, hdr.Header.Get("Content-Type"), hdr.Filename, "")
	case strings.TrimSpace(r.FormValue("text")) != "":
		res, err = importer.FromBytes([]byte(r.FormValue("text")), "text/plain", "", "")
	default:
		err = errors.New("provide a URL, a file or pasted text")
	}
	if err != nil {
		s.failures.Fail(ipKey)
		s.log.Warn("import failed", "user", u.Username, "err", err)
		s.importError(w, r, "Import failed: "+err.Error())
		return
	}
	rec := res.Recipe
	rec.OwnerID = u.ID
	rec.FolderID = optFolder(r.FormValue("folder"))
	s.recipeForm(w, r, http.StatusOK, "Review imported recipe", recipeFormData{Recipe: rec, Action: "/recipes", CanMove: true, Imported: true, Warning: res.Warning}, "")
}

func hasFile(r *http.Request) bool {
	if r.MultipartForm == nil {
		return false
	}
	fh := r.MultipartForm.File["file"]
	return len(fh) > 0 && fh[0].Size > 0
}

func (s *Server) importError(w http.ResponseWriter, r *http.Request, msg string) {
	s.render(w, r, http.StatusBadRequest, "import.html", pageData{Title: "Import", Error: msg, Data: map[string]any{
		"Folder": r.FormValue("folder"), "MaxMB": s.cfg.ImportMaxSize >> 20,
	}})
}

func itoaMB(n int64) string {
	return strconv.FormatInt(n>>20, 10) + " MB"
}
