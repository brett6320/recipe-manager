package recipes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound is returned when a row does not exist or is not visible.
var ErrNotFound = errors.New("not found")

// Store persists recipes and related entities.
type Store struct {
	db *sql.DB
}

// NewStore wraps db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// accessCTE yields, for user ?1, the set of (recipe_id, perm) pairs the user
// can reach through ownership, direct recipe shares, or shares on any
// ancestor folder (shares on folders apply recursively). Callers bind the
// user id as the first parameter.
const accessCTE = `
WITH RECURSIVE
grantees(gtype, gid) AS (
    SELECT 'user', ?1
    UNION ALL
    SELECT 'group', group_id FROM group_members WHERE user_id = ?1
),
folder_grants(folder_id, perm) AS (
    SELECT s.subject_id, s.perm FROM shares s JOIN grantees g ON s.grantee_type = g.gtype AND s.grantee_id = g.gid
    WHERE s.subject_type = 'folder'
    UNION ALL
    SELECT f.id, fg.perm FROM folders f JOIN folder_grants fg ON f.parent_id = fg.folder_id
),
access(recipe_id, perm) AS (
    SELECT id, 'owner' FROM recipes WHERE owner_id = ?1
    UNION ALL
    SELECT s.subject_id, s.perm FROM shares s JOIN grantees g ON s.grantee_type = g.gtype AND s.grantee_id = g.gid
    WHERE s.subject_type = 'recipe'
    UNION ALL
    SELECT r.id, fg.perm FROM recipes r JOIN folder_grants fg ON r.folder_id = fg.folder_id
),
best(recipe_id, perm) AS (
    SELECT recipe_id, MAX(CASE perm WHEN 'owner' THEN 3 WHEN 'edit' THEN 2 ELSE 1 END) FROM access GROUP BY recipe_id
)`

func permFromRank(n int) Perm {
	switch n {
	case 3:
		return PermOwner
	case 2:
		return PermEdit
	case 1:
		return PermView
	}
	return PermNone
}

// Access returns the caller's permission on a recipe.
func (s *Store) Access(ctx context.Context, userID, recipeID int64) (Perm, error) {
	var rank sql.NullInt64
	err := s.db.QueryRowContext(ctx, accessCTE+` SELECT perm FROM best WHERE recipe_id = ?2`, userID, recipeID).Scan(&rank)
	if errors.Is(err, sql.ErrNoRows) {
		return PermNone, nil
	}
	if err != nil {
		return PermNone, err
	}
	return permFromRank(int(rank.Int64)), nil
}

// FolderAccess returns the caller's permission on a folder (owner, or via a
// share on it or any ancestor).
func (s *Store) FolderAccess(ctx context.Context, userID, folderID int64) (Perm, error) {
	var rank sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
WITH RECURSIVE
grantees(gtype, gid) AS (
    SELECT 'user', ?1 UNION ALL SELECT 'group', group_id FROM group_members WHERE user_id = ?1
),
ancestors(id) AS (
    SELECT ?2 UNION ALL SELECT f.parent_id FROM folders f JOIN ancestors a ON f.id = a.id WHERE f.parent_id IS NOT NULL
)
SELECT MAX(rank) FROM (
    SELECT 3 AS rank FROM folders WHERE id = ?2 AND owner_id = ?1
    UNION ALL
    SELECT CASE s.perm WHEN 'edit' THEN 2 ELSE 1 END FROM shares s
      JOIN grantees g ON s.grantee_type = g.gtype AND s.grantee_id = g.gid
     WHERE s.subject_type = 'folder' AND s.subject_id IN (SELECT id FROM ancestors)
)`, userID, folderID).Scan(&rank)
	if err != nil {
		return PermNone, err
	}
	if !rank.Valid {
		return PermNone, nil
	}
	return permFromRank(int(rank.Int64)), nil
}

// --- recipes ---

const recipeCols = `r.id, r.owner_id, u.username, r.folder_id, r.title, r.description, r.servings, r.prep_minutes, r.cook_minutes, r.source_url, r.image_url, r.notes, r.created_at, r.updated_at`

func scanRecipe(row interface{ Scan(...any) error }) (*Recipe, error) {
	var r Recipe
	var folder sql.NullInt64
	var prep, cook sql.NullInt64
	var created, updated string
	if err := row.Scan(&r.ID, &r.OwnerID, &r.OwnerName, &folder, &r.Title, &r.Description, &r.Servings, &prep, &cook, &r.SourceURL, &r.ImageURL, &r.Notes, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if folder.Valid {
		r.FolderID = &folder.Int64
	}
	if prep.Valid {
		v := int(prep.Int64)
		r.PrepMinutes = &v
	}
	if cook.Valid {
		v := int(cook.Int64)
		r.CookMinutes = &v
	}
	r.CreatedAt, r.UpdatedAt = parseTime(created), parseTime(updated)
	return &r, nil
}

// Get loads a recipe if userID may view it.
func (s *Store) Get(ctx context.Context, userID, id int64) (*Recipe, Perm, error) {
	perm, err := s.Access(ctx, userID, id)
	if err != nil {
		return nil, PermNone, err
	}
	if !perm.CanView() {
		return nil, PermNone, ErrNotFound
	}
	r, err := scanRecipe(s.db.QueryRowContext(ctx, `SELECT `+recipeCols+` FROM recipes r JOIN users u ON u.id = r.owner_id WHERE r.id = ?`, id))
	if err != nil {
		return nil, PermNone, err
	}
	if err := s.loadParts(ctx, r); err != nil {
		return nil, PermNone, err
	}
	return r, perm, nil
}

func (s *Store) loadParts(ctx context.Context, r *Recipe) error {
	var err error
	if r.Ingredients, err = s.lines(ctx, `SELECT text FROM recipe_ingredients WHERE recipe_id = ? ORDER BY pos`, r.ID); err != nil {
		return err
	}
	if r.Steps, err = s.lines(ctx, `SELECT text FROM recipe_steps WHERE recipe_id = ? ORDER BY pos`, r.ID); err != nil {
		return err
	}
	r.Tags, err = s.lines(ctx, `SELECT tag FROM recipe_tags WHERE recipe_id = ? ORDER BY tag`, r.ID)
	return err
}

func (s *Store) lines(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Create inserts a recipe owned by r.OwnerID.
func (s *Store) Create(ctx context.Context, r *Recipe) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.FolderID != nil {
		if err := s.assertOwnFolder(ctx, r.OwnerID, *r.FolderID); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO recipes (owner_id, folder_id, title, description, servings, prep_minutes, cook_minutes, source_url, image_url, notes) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		r.OwnerID, r.FolderID, r.Title, r.Description, r.Servings, r.PrepMinutes, r.CookMinutes, r.SourceURL, r.ImageURL, r.Notes)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	if err := s.writeParts(ctx, tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

// Update rewrites a recipe. The caller must have checked edit permission.
// Only the owner may move it between folders.
func (s *Store) Update(ctx context.Context, r *Recipe, moveFolder bool) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if moveFolder && r.FolderID != nil {
		// Must run before BeginTx: the pool holds a single connection.
		if err := s.assertOwnFolder(ctx, r.OwnerID, *r.FolderID); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if moveFolder {
		if _, err := tx.ExecContext(ctx, `UPDATE recipes SET folder_id = ? WHERE id = ?`, r.FolderID, r.ID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE recipes SET title=?, description=?, servings=?, prep_minutes=?, cook_minutes=?, source_url=?, image_url=?, notes=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`,
		r.Title, r.Description, r.Servings, r.PrepMinutes, r.CookMinutes, r.SourceURL, r.ImageURL, r.Notes, r.ID); err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM recipe_ingredients WHERE recipe_id = ?`,
		`DELETE FROM recipe_steps WHERE recipe_id = ?`,
		`DELETE FROM recipe_tags WHERE recipe_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, r.ID); err != nil {
			return err
		}
	}
	if err := s.writeParts(ctx, tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) writeParts(ctx context.Context, tx *sql.Tx, r *Recipe) error {
	for i, t := range r.Ingredients {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recipe_ingredients (recipe_id, pos, text) VALUES (?,?,?)`, r.ID, i, t); err != nil {
			return err
		}
	}
	for i, t := range r.Steps {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recipe_steps (recipe_id, pos, text) VALUES (?,?,?)`, r.ID, i, t); err != nil {
			return err
		}
	}
	for _, t := range r.Tags {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO recipe_tags (recipe_id, tag) VALUES (?,?)`, r.ID, t); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes a recipe owned by userID.
func (s *Store) Delete(ctx context.Context, userID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM recipes WHERE id = ? AND owner_id = ?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Summary is a list row.
type Summary struct {
	ID          int64
	Title       string
	Description string
	OwnerName   string
	OwnerID     int64
	Tags        []string
	Perm        Perm
	Minutes     int
	UpdatedAt   time.Time
}

// ListOptions filters list queries.
type ListOptions struct {
	Query    string
	Tag      string
	FolderID *int64 // own recipes in this folder (nil = root) when InFolder is set
	InFolder bool
	Shared   bool // only recipes not owned by the user
	Limit    int
}

// List returns recipes visible to userID matching opts, newest first.
func (s *Store) List(ctx context.Context, userID int64, opts ListOptions) ([]Summary, error) {
	var where []string
	args := []any{userID}
	add := func(cond string, a ...any) {
		where = append(where, cond)
		args = append(args, a...)
	}
	if opts.InFolder {
		if opts.FolderID == nil {
			add(`r.owner_id = ?1 AND r.folder_id IS NULL`)
		} else {
			add(`r.owner_id = ?1 AND r.folder_id = ?`, *opts.FolderID)
		}
	}
	if opts.Shared {
		add(`r.owner_id != ?1`)
	}
	if q := strings.TrimSpace(opts.Query); q != "" {
		like := "%" + escapeLike(q) + "%"
		add(`(r.title LIKE ? ESCAPE '\' OR r.description LIKE ? ESCAPE '\' OR EXISTS (SELECT 1 FROM recipe_ingredients i WHERE i.recipe_id = r.id AND i.text LIKE ? ESCAPE '\') OR EXISTS (SELECT 1 FROM recipe_tags t WHERE t.recipe_id = r.id AND t.tag LIKE ? ESCAPE '\'))`, like, like, like, like)
	}
	if opts.Tag != "" {
		add(`EXISTS (SELECT 1 FROM recipe_tags t WHERE t.recipe_id = r.id AND t.tag = ?)`, strings.ToLower(opts.Tag))
	}
	limit := opts.Limit
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	q := accessCTE + ` SELECT r.id, r.title, r.description, u.username, r.owner_id, b.perm, COALESCE(r.prep_minutes,0)+COALESCE(r.cook_minutes,0), r.updated_at
		FROM best b JOIN recipes r ON r.id = b.recipe_id JOIN users u ON u.id = r.owner_id`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, " AND ") //nolint:gosec // fragments are compile-time literals; user input only enters via bound args
	}
	q += ` ORDER BY r.updated_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...) //nolint:gosec // WHERE fragments are static literals; all values are bound parameters
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Summary
	for rows.Next() {
		var sm Summary
		var rank int
		var updated string
		if err := rows.Scan(&sm.ID, &sm.Title, &sm.Description, &sm.OwnerName, &sm.OwnerID, &rank, &sm.Minutes, &updated); err != nil {
			return nil, err
		}
		sm.Perm = permFromRank(rank)
		sm.UpdatedAt = parseTime(updated)
		if len(sm.Description) > 160 {
			sm.Description = truncate(sm.Description, 157) + "…"
		}
		out = append(out, sm)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Tags, err = s.lines(ctx, `SELECT tag FROM recipe_tags WHERE recipe_id = ? ORDER BY tag`, out[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// Tags returns all tags on recipes visible to userID with counts.
func (s *Store) Tags(ctx context.Context, userID int64) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, accessCTE+` SELECT t.tag, COUNT(*) FROM best b JOIN recipe_tags t ON t.recipe_id = b.recipe_id GROUP BY t.tag ORDER BY t.tag`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, rows.Err()
}

// --- folders ---

func (s *Store) assertOwnFolder(ctx context.Context, userID, folderID int64) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM folders WHERE id = ? AND owner_id = ?`, folderID, userID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return errors.New("folder not found")
	}
	return nil
}

// Folder loads one folder by id (no access check; callers use FolderAccess).
func (s *Store) Folder(ctx context.Context, id int64) (*Folder, error) {
	var f Folder
	var parent sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, owner_id, parent_id, name FROM folders WHERE id = ?`, id).Scan(&f.ID, &f.OwnerID, &parent, &f.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if parent.Valid {
		f.ParentID = &parent.Int64
	}
	f.Path, err = s.folderPath(ctx, f.ID)
	return &f, err
}

func (s *Store) folderPath(ctx context.Context, id int64) (string, error) {
	rows, err := s.db.QueryContext(ctx, `WITH RECURSIVE a(id, parent_id, name, depth) AS (
		SELECT id, parent_id, name, 0 FROM folders WHERE id = ?
		UNION ALL SELECT f.id, f.parent_id, f.name, a.depth+1 FROM folders f JOIN a ON f.id = a.parent_id)
		SELECT name FROM a ORDER BY depth DESC`, id)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	var parts []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return "", err
		}
		parts = append(parts, n)
	}
	return strings.Join(parts, " / "), rows.Err()
}

// Breadcrumb returns the ancestor chain for a folder, root first.
func (s *Store) Breadcrumb(ctx context.Context, id int64) ([]Folder, error) {
	rows, err := s.db.QueryContext(ctx, `WITH RECURSIVE a(id, parent_id, name, owner_id, depth) AS (
		SELECT id, parent_id, name, owner_id, 0 FROM folders WHERE id = ?
		UNION ALL SELECT f.id, f.parent_id, f.name, f.owner_id, a.depth+1 FROM folders f JOIN a ON f.id = a.parent_id)
		SELECT id, parent_id, name, owner_id FROM a ORDER BY depth DESC`, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Folder
	for rows.Next() {
		var f Folder
		var parent sql.NullInt64
		if err := rows.Scan(&f.ID, &parent, &f.Name, &f.OwnerID); err != nil {
			return nil, err
		}
		if parent.Valid {
			f.ParentID = &parent.Int64
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Subfolders lists children of parent (nil = root) owned by userID.
func (s *Store) Subfolders(ctx context.Context, userID int64, parent *int64) ([]Folder, error) {
	var rows *sql.Rows
	var err error
	if parent == nil {
		rows, err = s.db.QueryContext(ctx, `SELECT id, owner_id, parent_id, name FROM folders WHERE owner_id = ? AND parent_id IS NULL ORDER BY name COLLATE NOCASE`, userID)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT id, owner_id, parent_id, name FROM folders WHERE parent_id = ? ORDER BY name COLLATE NOCASE`, *parent)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanFolders(rows)
}

func scanFolders(rows *sql.Rows) ([]Folder, error) {
	var out []Folder
	for rows.Next() {
		var f Folder
		var parent sql.NullInt64
		if err := rows.Scan(&f.ID, &f.OwnerID, &parent, &f.Name); err != nil {
			return nil, err
		}
		if parent.Valid {
			f.ParentID = &parent.Int64
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// AllFolders returns every folder owned by userID with display paths,
// sorted by path. Used for "move to" selectors.
func (s *Store) AllFolders(ctx context.Context, userID int64) ([]Folder, error) {
	rows, err := s.db.QueryContext(ctx, `WITH RECURSIVE t(id, owner_id, parent_id, name, path) AS (
		SELECT id, owner_id, parent_id, name, name FROM folders WHERE owner_id = ? AND parent_id IS NULL
		UNION ALL SELECT f.id, f.owner_id, f.parent_id, f.name, t.path || ' / ' || f.name FROM folders f JOIN t ON f.parent_id = t.id)
		SELECT id, owner_id, parent_id, name, path FROM t ORDER BY path COLLATE NOCASE`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Folder
	for rows.Next() {
		var f Folder
		var parent sql.NullInt64
		if err := rows.Scan(&f.ID, &f.OwnerID, &parent, &f.Name, &f.Path); err != nil {
			return nil, err
		}
		if parent.Valid {
			f.ParentID = &parent.Int64
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CreateFolder adds a folder under parent (nil = root).
func (s *Store) CreateFolder(ctx context.Context, userID int64, parent *int64, name string) (int64, error) {
	name = Clean(name, MaxFolderName)
	if name == "" || strings.Contains(name, "/") {
		return 0, errors.New("folder name is required and may not contain '/'")
	}
	if parent != nil {
		if err := s.assertOwnFolder(ctx, userID, *parent); err != nil {
			return 0, err
		}
		depth, err := s.depth(ctx, *parent)
		if err != nil {
			return 0, err
		}
		if depth >= 10 {
			return 0, errors.New("folders may be nested at most 10 levels deep")
		}
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO folders (owner_id, parent_id, name) VALUES (?,?,?)`, userID, parent, name)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, errors.New("a folder with that name already exists here")
		}
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

func (s *Store) depth(ctx context.Context, id int64) (int, error) {
	var d int
	err := s.db.QueryRowContext(ctx, `WITH RECURSIVE a(id, parent_id, depth) AS (
		SELECT id, parent_id, 1 FROM folders WHERE id = ?
		UNION ALL SELECT f.id, f.parent_id, a.depth+1 FROM folders f JOIN a ON f.id = a.parent_id)
		SELECT MAX(depth) FROM a`, id).Scan(&d)
	return d, err
}

// RenameFolder renames a folder owned by userID.
func (s *Store) RenameFolder(ctx context.Context, userID, id int64, name string) error {
	name = Clean(name, MaxFolderName)
	if name == "" || strings.Contains(name, "/") {
		return errors.New("folder name is required and may not contain '/'")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE folders SET name = ? WHERE id = ? AND owner_id = ?`, name, id, userID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return errors.New("a folder with that name already exists here")
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteFolder removes a folder owned by userID. Recipes inside (at any
// depth) move to the folder's parent; subfolders are deleted.
func (s *Store) DeleteFolder(ctx context.Context, userID, id int64) error {
	f, err := s.Folder(ctx, id)
	if err != nil {
		return err
	}
	if f.OwnerID != userID {
		return ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `WITH RECURSIVE d(id) AS (SELECT ? UNION ALL SELECT f.id FROM folders f JOIN d ON f.parent_id = d.id)
		UPDATE recipes SET folder_id = ? WHERE folder_id IN (SELECT id FROM d)`, id, f.ParentID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `WITH RECURSIVE d(id) AS (SELECT ? UNION ALL SELECT f.id FROM folders f JOIN d ON f.parent_id = d.id)
		DELETE FROM shares WHERE subject_type = 'folder' AND subject_id IN (SELECT id FROM d)`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM folders WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// MoveFolder re-parents a folder owned by userID; cycles are rejected.
func (s *Store) MoveFolder(ctx context.Context, userID, id int64, newParent *int64) error {
	if err := s.assertOwnFolder(ctx, userID, id); err != nil {
		return err
	}
	if newParent != nil {
		if *newParent == id {
			return errors.New("cannot move a folder into itself")
		}
		if err := s.assertOwnFolder(ctx, userID, *newParent); err != nil {
			return err
		}
		var n int
		if err := s.db.QueryRowContext(ctx, `WITH RECURSIVE d(id) AS (SELECT ? UNION ALL SELECT f.id FROM folders f JOIN d ON f.parent_id = d.id)
			SELECT COUNT(*) FROM d WHERE id = ?`, id, *newParent).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return errors.New("cannot move a folder into its own subfolder")
		}
	}
	_, err := s.db.ExecContext(ctx, `UPDATE folders SET parent_id = ? WHERE id = ?`, newParent, id)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errors.New("a folder with that name already exists there")
	}
	return err
}

// SharedFolders lists folders shared to userID (directly or via group)
// that the user does not own.
func (s *Store) SharedFolders(ctx context.Context, userID int64) ([]Folder, error) {
	rows, err := s.db.QueryContext(ctx, `WITH grantees(gtype, gid) AS (
		SELECT 'user', ?1 UNION ALL SELECT 'group', group_id FROM group_members WHERE user_id = ?1)
		SELECT DISTINCT f.id, f.owner_id, f.parent_id, f.name FROM shares s JOIN grantees g ON s.grantee_type = g.gtype AND s.grantee_id = g.gid
		JOIN folders f ON f.id = s.subject_id WHERE s.subject_type = 'folder' AND f.owner_id != ?1 ORDER BY f.name COLLATE NOCASE`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out, err := scanFolders(rows)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Path, err = s.folderPath(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// RecipesInSharedFolder lists recipes in a folder the caller can view via a
// share (any owner), newest first.
func (s *Store) RecipesInFolder(ctx context.Context, userID, folderID int64) ([]Summary, error) {
	rows, err := s.db.QueryContext(ctx, accessCTE+` SELECT r.id, r.title, r.description, u.username, r.owner_id, b.perm, COALESCE(r.prep_minutes,0)+COALESCE(r.cook_minutes,0), r.updated_at
		FROM best b JOIN recipes r ON r.id = b.recipe_id JOIN users u ON u.id = r.owner_id WHERE r.folder_id = ?2 ORDER BY r.title COLLATE NOCASE`, userID, folderID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Summary
	for rows.Next() {
		var sm Summary
		var rank int
		var updated string
		if err := rows.Scan(&sm.ID, &sm.Title, &sm.Description, &sm.OwnerName, &sm.OwnerID, &rank, &sm.Minutes, &updated); err != nil {
			return nil, err
		}
		sm.Perm = permFromRank(rank)
		sm.UpdatedAt = parseTime(updated)
		out = append(out, sm)
	}
	return out, rows.Err()
}

// --- groups ---

// CreateGroup makes a group owned by userID with the owner as first member.
func (s *Store) CreateGroup(ctx context.Context, userID int64, name string) (int64, error) {
	name = Clean(name, 60)
	if name == "" {
		return 0, errors.New("group name is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO groups (name, owner_id) VALUES (?,?)`, name, userID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, errors.New("a group with that name already exists")
		}
		return 0, err
	}
	id, _ := res.LastInsertId()
	if _, err := tx.ExecContext(ctx, `INSERT INTO group_members (group_id, user_id) VALUES (?,?)`, id, userID); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// Group loads a group.
func (s *Store) Group(ctx context.Context, id int64) (*Group, error) {
	var g Group
	err := s.db.QueryRowContext(ctx, `SELECT g.id, g.name, g.owner_id, u.username, (SELECT COUNT(*) FROM group_members m WHERE m.group_id = g.id) FROM groups g JOIN users u ON u.id = g.owner_id WHERE g.id = ?`, id).
		Scan(&g.ID, &g.Name, &g.OwnerID, &g.OwnerName, &g.Members)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &g, err
}

// ListGroups returns all groups (names are not secret within an instance).
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT g.id, g.name, g.owner_id, u.username, (SELECT COUNT(*) FROM group_members m WHERE m.group_id = g.id) FROM groups g JOIN users u ON u.id = g.owner_id ORDER BY g.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.OwnerID, &g.OwnerName, &g.Members); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Member is a group member row.
type Member struct {
	UserID      int64
	Username    string
	DisplayName string
}

// GroupMembers lists members.
func (s *Store) GroupMembers(ctx context.Context, groupID int64) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id, u.username, u.display_name FROM group_members m JOIN users u ON u.id = m.user_id WHERE m.group_id = ? ORDER BY u.username`, groupID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Username, &m.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddMember adds a user by username.
func (s *Store) AddMember(ctx context.Context, groupID int64, username string) error {
	var uid int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE username = ?`, strings.ToLower(strings.TrimSpace(username))).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("no such user")
	}
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)`, groupID, uid)
	return err
}

// RemoveMember removes a user from a group.
func (s *Store) RemoveMember(ctx context.Context, groupID, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, groupID, userID)
	return err
}

// DeleteGroup removes a group and its shares.
func (s *Store) DeleteGroup(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM shares WHERE grantee_type = 'group' AND grantee_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// --- shares ---

// Shares lists grants on a subject.
func (s *Store) Shares(ctx context.Context, subjectType string, subjectID int64) ([]Share, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id, s.subject_type, s.subject_id, s.grantee_type, s.grantee_id, s.perm,
		CASE s.grantee_type WHEN 'user' THEN (SELECT username FROM users WHERE id = s.grantee_id) ELSE (SELECT name FROM groups WHERE id = s.grantee_id) END
		FROM shares s WHERE s.subject_type = ? AND s.subject_id = ? ORDER BY s.grantee_type, 7`, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Share
	for rows.Next() {
		var sh Share
		var name sql.NullString
		var perm string
		if err := rows.Scan(&sh.ID, &sh.SubjectType, &sh.SubjectID, &sh.GranteeType, &sh.GranteeID, &perm, &name); err != nil {
			return nil, err
		}
		sh.Perm = Perm(perm)
		sh.GranteeName = name.String
		out = append(out, sh)
	}
	return out, rows.Err()
}

// AddShare grants perm on a subject to a user (by username) or group (by
// id). The caller must own the subject.
func (s *Store) AddShare(ctx context.Context, by int64, subjectType string, subjectID int64, granteeType, grantee string, perm Perm) error {
	if perm != PermView && perm != PermEdit {
		return errors.New("permission must be view or edit")
	}
	if subjectType != "recipe" && subjectType != "folder" {
		return errors.New("bad subject")
	}
	var gid int64
	switch granteeType {
	case "user":
		err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE username = ?`, strings.ToLower(strings.TrimSpace(grantee))).Scan(&gid)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("no such user")
		}
		if err != nil {
			return err
		}
		if gid == by {
			return errors.New("you already own this")
		}
	case "group":
		if _, err := fmt.Sscan(grantee, &gid); err != nil {
			return errors.New("bad group")
		}
		if _, err := s.Group(ctx, gid); err != nil {
			return errors.New("no such group")
		}
	default:
		return errors.New("bad grantee type")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO shares (subject_type, subject_id, grantee_type, grantee_id, perm, created_by) VALUES (?,?,?,?,?,?)
		ON CONFLICT(subject_type, subject_id, grantee_type, grantee_id) DO UPDATE SET perm = excluded.perm`, subjectType, subjectID, granteeType, gid, string(perm), by)
	return err
}

// RemoveShare deletes a share by id if the subject is owned by userID.
func (s *Store) RemoveShare(ctx context.Context, userID, shareID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM shares WHERE id = ? AND (
		(subject_type = 'recipe' AND subject_id IN (SELECT id FROM recipes WHERE owner_id = ?)) OR
		(subject_type = 'folder' AND subject_id IN (SELECT id FROM folders WHERE owner_id = ?)))`, shareID, userID, userID)
	return err
}
