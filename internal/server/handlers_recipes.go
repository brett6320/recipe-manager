package server

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/brett6320/recipe-manager/internal/auth"
	"github.com/brett6320/recipe-manager/internal/recipes"
)

var backRe = regexp.MustCompile(`^/(recipes|folders)/[0-9]+$`)

func optFolder(v string) *int64 {
	if v == "" || v == "0" {
		return nil
	}
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		return nil
	}
	return &id
}

func optInt(v string) *int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}
	return &n
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

func splitTags(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' })
}

// --- home / browse ---

type browseData struct {
	Folder     *recipes.Folder
	Crumbs     []recipes.Folder
	Subfolders []recipes.Folder
	Recipes    []recipes.Summary
	Shared     []recipes.Summary
	SharedDirs []recipes.Folder
	Tags       map[string]int
	AllFolders []recipes.Folder
	Shares     []recipes.Share
	Groups     []recipes.Group
	Perm       recipes.Perm
	IsOwner    bool
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	ctx := r.Context()
	d := browseData{Perm: recipes.PermOwner, IsOwner: true}
	var err error
	if d.Subfolders, err = s.recipes.Subfolders(ctx, u.ID, nil); err != nil {
		s.serverError(w, r, err)
		return
	}
	if d.Recipes, err = s.recipes.List(ctx, u.ID, recipes.ListOptions{InFolder: true}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if d.Shared, err = s.recipes.List(ctx, u.ID, recipes.ListOptions{Shared: true, Limit: 50}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if d.SharedDirs, err = s.recipes.SharedFolders(ctx, u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if d.Tags, err = s.recipes.Tags(ctx, u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "index.html", pageData{Title: "Recipes", Data: d})
}

func (s *Server) handleFolder(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	ctx := r.Context()
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	perm, err := s.recipes.FolderAccess(ctx, u.ID, id)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !perm.CanView() {
		http.NotFound(w, r)
		return
	}
	f, err := s.recipes.Folder(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := browseData{Folder: f, Perm: perm, IsOwner: f.OwnerID == u.ID}
	if d.Crumbs, err = s.recipes.Breadcrumb(ctx, id); err != nil {
		s.serverError(w, r, err)
		return
	}
	if !d.IsOwner {
		// Trim crumbs to the shared subtree the viewer can actually reach.
		for i := range d.Crumbs {
			if p, _ := s.recipes.FolderAccess(ctx, u.ID, d.Crumbs[i].ID); p.CanView() {
				d.Crumbs = d.Crumbs[i:]
				break
			}
		}
	}
	if d.Subfolders, err = s.recipes.Subfolders(ctx, u.ID, &id); err != nil {
		s.serverError(w, r, err)
		return
	}
	if d.Recipes, err = s.recipes.RecipesInFolder(ctx, u.ID, id); err != nil {
		s.serverError(w, r, err)
		return
	}
	if d.IsOwner {
		if d.AllFolders, err = s.recipes.AllFolders(ctx, u.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
		if d.Shares, err = s.recipes.Shares(ctx, "folder", id); err != nil {
			s.serverError(w, r, err)
			return
		}
		if d.Groups, err = s.recipes.ListGroups(ctx); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.render(w, r, http.StatusOK, "folder.html", pageData{Title: f.Name, Data: d})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	q := recipes.Clean(r.URL.Query().Get("q"), 100)
	tag := recipes.Clean(r.URL.Query().Get("tag"), recipes.MaxTag)
	list, err := s.recipes.List(r.Context(), u.ID, recipes.ListOptions{Query: q, Tag: tag})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "search.html", pageData{Title: "Search", Data: map[string]any{"Query": q, "Tag": tag, "Recipes": list}})
}

// --- folders ---

func (s *Server) folderRedirect(w http.ResponseWriter, r *http.Request, id *int64) {
	if id == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/folders/"+strconv.FormatInt(*id, 10), http.StatusSeeOther)
}

func (s *Server) handleFolderCreate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	parent := optFolder(r.FormValue("parent"))
	if _, err := s.recipes.CreateFolder(r.Context(), u.ID, parent, r.FormValue("name")); err != nil {
		s.setFlash(w, err.Error())
	}
	s.folderRedirect(w, r, parent)
}

func (s *Server) handleFolderRename(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := s.recipes.RenameFolder(r.Context(), u.ID, id, r.FormValue("name")); err != nil {
		s.setFlash(w, err.Error())
	}
	s.folderRedirect(w, r, &id)
}

func (s *Server) handleFolderMove(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := s.recipes.MoveFolder(r.Context(), u.ID, id, optFolder(r.FormValue("parent"))); err != nil {
		s.setFlash(w, err.Error())
	}
	s.folderRedirect(w, r, &id)
}

func (s *Server) handleFolderDelete(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := s.recipes.Folder(r.Context(), id)
	if err != nil || f.OwnerID != u.ID {
		http.NotFound(w, r)
		return
	}
	if err := s.recipes.DeleteFolder(r.Context(), u.ID, id); err != nil {
		s.setFlash(w, err.Error())
		s.folderRedirect(w, r, &id)
		return
	}
	s.setFlash(w, "Folder deleted; its recipes were moved up one level.")
	s.folderRedirect(w, r, f.ParentID)
}

// --- recipes ---

type recipeFormData struct {
	Recipe     *recipes.Recipe
	Folders    []recipes.Folder
	Action     string
	CanMove    bool
	Imported   bool
	Warning    string
	Ingredient string
	Steps      string
	Tags       string
}

func (s *Server) recipeForm(w http.ResponseWriter, r *http.Request, status int, title string, d recipeFormData, errMsg string) {
	u := currentUser(r)
	var err error
	if d.Folders, err = s.recipes.AllFolders(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Ingredient = strings.Join(d.Recipe.Ingredients, "\n")
	d.Steps = strings.Join(d.Recipe.Steps, "\n")
	d.Tags = strings.Join(d.Recipe.Tags, ", ")
	s.render(w, r, status, "recipe_form.html", pageData{Title: title, Error: errMsg, Data: d})
}

func (s *Server) handleRecipeNew(w http.ResponseWriter, r *http.Request) {
	rec := &recipes.Recipe{FolderID: optFolder(r.URL.Query().Get("folder"))}
	s.recipeForm(w, r, http.StatusOK, "New recipe", recipeFormData{Recipe: rec, Action: "/recipes", CanMove: true}, "")
}

func recipeFromForm(r *http.Request, rec *recipes.Recipe) {
	rec.Title = r.FormValue("title")
	rec.Description = r.FormValue("description")
	rec.Servings = r.FormValue("servings")
	rec.PrepMinutes = optInt(r.FormValue("prep_minutes"))
	rec.CookMinutes = optInt(r.FormValue("cook_minutes"))
	rec.SourceURL = r.FormValue("source_url")
	rec.ImageURL = r.FormValue("image_url")
	rec.Notes = r.FormValue("notes")
	rec.Ingredients = splitLines(r.FormValue("ingredients"))
	rec.Steps = splitLines(r.FormValue("steps"))
	rec.Tags = splitTags(r.FormValue("tags"))
}

func (s *Server) handleRecipeCreate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	rec := &recipes.Recipe{OwnerID: u.ID, FolderID: optFolder(r.FormValue("folder"))}
	recipeFromForm(r, rec)
	if err := s.recipes.Create(r.Context(), rec); err != nil {
		s.recipeForm(w, r, http.StatusBadRequest, "New recipe", recipeFormData{Recipe: rec, Action: "/recipes", CanMove: true}, err.Error())
		return
	}
	http.Redirect(w, r, "/recipes/"+strconv.FormatInt(rec.ID, 10), http.StatusSeeOther)
}

func (s *Server) loadRecipe(w http.ResponseWriter, r *http.Request) (*recipes.Recipe, recipes.Perm, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return nil, recipes.PermNone, false
	}
	rec, perm, err := s.recipes.Get(r.Context(), currentUser(r).ID, id)
	if err != nil {
		if errors.Is(err, recipes.ErrNotFound) {
			http.NotFound(w, r)
		} else {
			s.serverError(w, r, err)
		}
		return nil, recipes.PermNone, false
	}
	return rec, perm, true
}

func (s *Server) handleRecipeView(w http.ResponseWriter, r *http.Request) {
	rec, perm, ok := s.loadRecipe(w, r)
	if !ok {
		return
	}
	u := currentUser(r)
	d := map[string]any{"Recipe": rec, "Perm": perm, "IsOwner": rec.OwnerID == u.ID}
	if rec.FolderID != nil {
		if f, err := s.recipes.Folder(r.Context(), *rec.FolderID); err == nil {
			d["Folder"] = f
		}
	}
	if rec.OwnerID == u.ID {
		shares, err := s.recipes.Shares(r.Context(), "recipe", rec.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		groups, err := s.recipes.ListGroups(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		folders, err := s.recipes.AllFolders(r.Context(), u.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		d["Shares"], d["Groups"], d["AllFolders"] = shares, groups, folders
	}
	s.render(w, r, http.StatusOK, "recipe.html", pageData{Title: rec.Title, Data: d})
}

func (s *Server) handleRecipeEdit(w http.ResponseWriter, r *http.Request) {
	rec, perm, ok := s.loadRecipe(w, r)
	if !ok {
		return
	}
	if !perm.CanEdit() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.recipeForm(w, r, http.StatusOK, "Edit "+rec.Title, recipeFormData{Recipe: rec, Action: "/recipes/" + strconv.FormatInt(rec.ID, 10), CanMove: perm == recipes.PermOwner}, "")
}

func (s *Server) handleRecipeUpdate(w http.ResponseWriter, r *http.Request) {
	rec, perm, ok := s.loadRecipe(w, r)
	if !ok {
		return
	}
	if !perm.CanEdit() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	recipeFromForm(r, rec)
	move := perm == recipes.PermOwner
	if move {
		rec.FolderID = optFolder(r.FormValue("folder"))
	}
	if err := s.recipes.Update(r.Context(), rec, move); err != nil {
		s.recipeForm(w, r, http.StatusBadRequest, "Edit "+rec.Title, recipeFormData{Recipe: rec, Action: "/recipes/" + strconv.FormatInt(rec.ID, 10), CanMove: move}, err.Error())
		return
	}
	http.Redirect(w, r, "/recipes/"+strconv.FormatInt(rec.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleRecipeMove(w http.ResponseWriter, r *http.Request) {
	rec, perm, ok := s.loadRecipe(w, r)
	if !ok {
		return
	}
	if perm != recipes.PermOwner {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rec.FolderID = optFolder(r.FormValue("folder"))
	if err := s.recipes.Update(r.Context(), rec, true); err != nil {
		s.setFlash(w, err.Error())
	}
	http.Redirect(w, r, "/recipes/"+strconv.FormatInt(rec.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleRecipeDelete(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := s.recipes.Delete(r.Context(), u.ID, id); err != nil {
		http.NotFound(w, r)
		return
	}
	s.setFlash(w, "Recipe deleted.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- export ---

// schemaRecipe is a schema.org/Recipe JSON-LD representation.
type schemaRecipe struct {
	Context      string   `json:"@context"`
	Type         string   `json:"@type"`
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	RecipeYield  string   `json:"recipeYield,omitempty"`
	PrepTime     string   `json:"prepTime,omitempty"`
	CookTime     string   `json:"cookTime,omitempty"`
	Image        string   `json:"image,omitempty"`
	URL          string   `json:"url,omitempty"`
	Keywords     string   `json:"keywords,omitempty"`
	Ingredients  []string `json:"recipeIngredient"`
	Instructions []string `json:"recipeInstructions"`
	Notes        string   `json:"comment,omitempty"`
}

func isoDuration(m *int) string {
	if m == nil || *m <= 0 {
		return ""
	}
	return "PT" + strconv.Itoa(*m) + "M"
}

func toSchema(rec *recipes.Recipe) schemaRecipe {
	return schemaRecipe{
		Context: "https://schema.org", Type: "Recipe", Name: rec.Title, Description: rec.Description,
		RecipeYield: rec.Servings, PrepTime: isoDuration(rec.PrepMinutes), CookTime: isoDuration(rec.CookMinutes),
		Image: rec.ImageURL, URL: rec.SourceURL, Keywords: strings.Join(rec.Tags, ", "),
		Ingredients: rec.Ingredients, Instructions: rec.Steps, Notes: rec.Notes,
	}
}

func (s *Server) handleRecipeExport(w http.ResponseWriter, r *http.Request) {
	rec, _, ok := s.loadRecipe(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\"recipe-"+strconv.FormatInt(rec.ID, 10)+".json\"")
	writeJSON(w, http.StatusOK, toSchema(rec))
}

func (s *Server) handleExportAll(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	list, err := s.recipes.List(r.Context(), u.ID, recipes.ListOptions{})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	out := make([]schemaRecipe, 0, len(list))
	for _, sm := range list {
		if sm.OwnerID != u.ID {
			continue
		}
		rec, _, err := s.recipes.Get(r.Context(), u.ID, sm.ID)
		if err != nil {
			continue
		}
		out = append(out, toSchema(rec))
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\"recipes.json\"")
	writeJSON(w, http.StatusOK, out)
}

// --- shares ---

func (s *Server) handleShareAdd(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	ctx := r.Context()
	subjectType := r.FormValue("subject_type")
	subjectID, err := strconv.ParseInt(r.FormValue("subject_id"), 10, 64)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var back string
	switch subjectType {
	case "recipe":
		rec, _, err := s.recipes.Get(ctx, u.ID, subjectID)
		if err != nil || rec.OwnerID != u.ID {
			http.NotFound(w, r)
			return
		}
		back = "/recipes/" + strconv.FormatInt(subjectID, 10)
	case "folder":
		f, err := s.recipes.Folder(ctx, subjectID)
		if err != nil || f.OwnerID != u.ID {
			http.NotFound(w, r)
			return
		}
		back = "/folders/" + strconv.FormatInt(subjectID, 10)
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	granteeType := r.FormValue("grantee_type")
	grantee := r.FormValue("user")
	if granteeType == "group" {
		grantee = r.FormValue("group")
	}
	if err := s.recipes.AddShare(ctx, u.ID, subjectType, subjectID, granteeType, grantee, recipes.Perm(r.FormValue("perm"))); err != nil {
		s.setFlash(w, err.Error())
	} else {
		s.setFlash(w, "Shared.")
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Server) handleShareRemove(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := s.recipes.RemoveShare(r.Context(), u.ID, id); err != nil {
		s.serverError(w, r, err)
		return
	}
	// Only same-site paths of a known shape are accepted; anything else goes home.
	back := "/"
	if m := backRe.FindString(r.FormValue("back")); m != "" {
		back = m
	}
	http.Redirect(w, r, back, http.StatusSeeOther) //nolint:gosec // back is constrained by backRe to a relative /recipes/N or /folders/N path
}

// --- groups ---

func (s *Server) canManageGroup(u *auth.User, g *recipes.Group) bool {
	return u.IsAdmin || g.OwnerID == u.ID
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.recipes.ListGroups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "groups.html", pageData{Title: "Groups", Data: groups})
}

func (s *Server) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, err := s.recipes.CreateGroup(r.Context(), u.ID, r.FormValue("name"))
	if err != nil {
		s.setFlash(w, err.Error())
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

func (s *Server) loadGroup(w http.ResponseWriter, r *http.Request) (*recipes.Group, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return nil, false
	}
	g, err := s.recipes.Group(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	return g, true
}

func (s *Server) handleGroupView(w http.ResponseWriter, r *http.Request) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	members, err := s.recipes.GroupMembers(r.Context(), g.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "group.html", pageData{Title: g.Name, Data: map[string]any{
		"Group": g, "Members": members, "CanManage": s.canManageGroup(currentUser(r), g),
	}})
}

func (s *Server) handleGroupAddMember(w http.ResponseWriter, r *http.Request) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	if !s.canManageGroup(currentUser(r), g) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.recipes.AddMember(r.Context(), g.ID, r.FormValue("username")); err != nil {
		s.setFlash(w, err.Error())
	}
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleGroupRemoveMember(w http.ResponseWriter, r *http.Request) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	u := currentUser(r)
	uid, err := strconv.ParseInt(r.PathValue("uid"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Members may remove themselves; otherwise manager rights are required.
	if uid != u.ID && !s.canManageGroup(u, g) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.recipes.RemoveMember(r.Context(), g.ID, uid); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(g.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	if !s.canManageGroup(currentUser(r), g) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.recipes.DeleteGroup(r.Context(), g.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setFlash(w, "Group deleted.")
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}
