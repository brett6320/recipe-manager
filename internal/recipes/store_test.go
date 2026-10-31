package recipes

import (
	"context"
	"errors"
	"testing"

	"github.com/brett6320/recipe-manager/internal/auth"
	"github.com/brett6320/recipe-manager/internal/db"
)

func setup(t *testing.T) (*Store, *auth.Store) {
	t.Helper()
	d, err := db.Open(context.Background(), t.TempDir()+"/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return NewStore(d), auth.NewStore(d)
}

func mkUser(t *testing.T, a *auth.Store, name string) int64 {
	t.Helper()
	u, err := a.CreateUser(context.Background(), name, name, false)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestAccessModel(t *testing.T) {
	ctx := context.Background()
	s, a := setup(t)
	alice := mkUser(t, a, "alice")
	bob := mkUser(t, a, "bob")
	carol := mkUser(t, a, "carol")

	// alice: /Dinners/Italian with a recipe inside, plus a root recipe.
	dinners, err := s.CreateFolder(ctx, alice, nil, "Dinners")
	if err != nil {
		t.Fatal(err)
	}
	italian, err := s.CreateFolder(ctx, alice, &dinners, "Italian")
	if err != nil {
		t.Fatal(err)
	}
	pasta := &Recipe{OwnerID: alice, FolderID: &italian, Title: "Pasta", Ingredients: []string{"pasta"}, Steps: []string{"boil"}}
	if err := s.Create(ctx, pasta); err != nil {
		t.Fatal(err)
	}
	toast := &Recipe{OwnerID: alice, Title: "Toast"}
	if err := s.Create(ctx, toast); err != nil {
		t.Fatal(err)
	}

	check := func(user, recipe int64, want Perm) {
		t.Helper()
		got, err := s.Access(ctx, user, recipe)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("user %d recipe %d: got %q want %q", user, recipe, got, want)
		}
	}

	check(alice, pasta.ID, PermOwner)
	check(bob, pasta.ID, PermNone)
	check(bob, toast.ID, PermNone)

	// Get refuses invisible recipes.
	if _, _, err := s.Get(ctx, bob, pasta.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}

	// Direct recipe share to bob: view.
	if err := s.AddShare(ctx, alice, "recipe", toast.ID, "user", "bob", PermView); err != nil {
		t.Fatal(err)
	}
	check(bob, toast.ID, PermView)
	check(carol, toast.ID, PermNone)

	// Folder share on the top-level folder cascades to nested recipe.
	g, err := s.CreateGroup(ctx, alice, "family")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddMember(ctx, g, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddShare(ctx, alice, "folder", dinners, "group", itoa(g), PermEdit); err != nil {
		t.Fatal(err)
	}
	check(carol, pasta.ID, PermEdit)
	check(bob, pasta.ID, PermNone) // bob not in group
	check(carol, toast.ID, PermNone)

	// Folder access resolves through ancestors too.
	if p, _ := s.FolderAccess(ctx, carol, italian); p != PermEdit {
		t.Errorf("carol on italian: %q", p)
	}
	if p, _ := s.FolderAccess(ctx, bob, italian); p != PermNone {
		t.Errorf("bob on italian: %q", p)
	}

	// Visible list for carol contains only pasta.
	list, err := s.List(ctx, carol, ListOptions{Shared: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != pasta.ID || list[0].Perm != PermEdit {
		t.Fatalf("carol list: %+v", list)
	}

	// Moving the recipe out of the shared tree revokes access.
	pasta.FolderID = nil
	if err := s.Update(ctx, pasta, true); err != nil {
		t.Fatal(err)
	}
	check(carol, pasta.ID, PermNone)

	// Leaving the group revokes group-derived access.
	pasta.FolderID = &italian
	if err := s.Update(ctx, pasta, true); err != nil {
		t.Fatal(err)
	}
	check(carol, pasta.ID, PermEdit)
	if err := s.RemoveMember(ctx, g, carol); err != nil {
		t.Fatal(err)
	}
	check(carol, pasta.ID, PermNone)

	// Non-owner cannot delete or remove shares.
	if err := s.Delete(ctx, bob, toast.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob delete: %v", err)
	}
	shares, _ := s.Shares(ctx, "recipe", toast.ID)
	if len(shares) != 1 {
		t.Fatal("expected one share")
	}
	_ = s.RemoveShare(ctx, bob, shares[0].ID)
	check(bob, toast.ID, PermView)
	_ = s.RemoveShare(ctx, alice, shares[0].ID)
	check(bob, toast.ID, PermNone)

	// Bob cannot file a recipe into alice's folder.
	bad := &Recipe{OwnerID: bob, FolderID: &italian, Title: "Sneaky"}
	if err := s.Create(ctx, bad); err == nil {
		t.Fatal("expected folder ownership error")
	}
}

func TestFolderOps(t *testing.T) {
	ctx := context.Background()
	s, a := setup(t)
	alice := mkUser(t, a, "alice")
	root, _ := s.CreateFolder(ctx, alice, nil, "A")
	child, _ := s.CreateFolder(ctx, alice, &root, "B")
	grand, _ := s.CreateFolder(ctx, alice, &child, "C")

	if err := s.MoveFolder(ctx, alice, root, &grand); err == nil {
		t.Fatal("cycle should be rejected")
	}
	if err := s.MoveFolder(ctx, alice, root, &root); err == nil {
		t.Fatal("self move should be rejected")
	}
	if _, err := s.CreateFolder(ctx, alice, &root, "B"); err == nil {
		t.Fatal("duplicate name should be rejected")
	}
	if _, err := s.CreateFolder(ctx, alice, nil, "x/y"); err == nil {
		t.Fatal("slash should be rejected")
	}
	r := &Recipe{OwnerID: alice, FolderID: &grand, Title: "Deep"}
	if err := s.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	f, _ := s.Folder(ctx, grand)
	if f.Path != "A / B / C" {
		t.Errorf("path %q", f.Path)
	}
	// Deleting B moves Deep to A and removes C.
	if err := s.DeleteFolder(ctx, alice, child); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Get(ctx, alice, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FolderID == nil || *got.FolderID != root {
		t.Errorf("recipe should be in A, got %v", got.FolderID)
	}
	if _, err := s.Folder(ctx, grand); !errors.Is(err, ErrNotFound) {
		t.Error("C should be gone")
	}
}

func TestSearchEscapesLike(t *testing.T) {
	ctx := context.Background()
	s, a := setup(t)
	alice := mkUser(t, a, "alice")
	_ = s.Create(ctx, &Recipe{OwnerID: alice, Title: "100% cocoa"})
	_ = s.Create(ctx, &Recipe{OwnerID: alice, Title: "plain"})
	list, err := s.List(ctx, alice, ListOptions{Query: "%"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Title != "100% cocoa" {
		t.Fatalf("wildcard should be literal, got %+v", list)
	}
}

func itoa(n int64) string {
	return string(rune('0' + n)) // ids in tests are single digits
}
