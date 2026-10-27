package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Exposure describes how reachable a service is. It feeds severity and SLA
// policy in later milestones.
type Exposure string

const (
	ExposureInternet Exposure = "internet"
	ExposureInternal Exposure = "internal"
	ExposurePrivate  Exposure = "private"
)

// File is the on-disk YAML document. Several files may be merged.
type File struct {
	Services []Service `yaml:"services"`
}

// Service is the unit of ownership: findings are grouped, routed and
// measured per service.
type Service struct {
	Name         string       `yaml:"name"`
	Owners       []string     `yaml:"owners"`
	SlackChannel string       `yaml:"slack_channel"`
	Exposure     Exposure     `yaml:"exposure"`
	Repositories []Repository `yaml:"repositories"`
}

// Repository links a Git repository to the Dependency-Track projects built
// from it (for example one project for the app SBOM and one for the image).
type Repository struct {
	Repo                    string   `yaml:"repo"`
	DependencyTrackProjects []string `yaml:"dependency_track_projects"`
}

// Projects returns the Dependency-Track project names for the repository.
// When none are listed, the last path segment of Repo is used.
func (r Repository) Projects() []string {
	if len(r.DependencyTrackProjects) > 0 {
		return r.DependencyTrackProjects
	}
	return []string{path.Base(r.Repo)}
}

// Match is the result of resolving a Dependency-Track project.
type Match struct {
	Service    *Service
	Repository string
}

// Inventory is a validated, indexed set of services.
type Inventory struct {
	services []Service
	byName   map[string]*Service
	byDTProj map[string]Match
}

// Empty returns an inventory with no services. Every lookup misses.
func Empty() *Inventory {
	inv, _ := build(nil)
	return inv
}

// Load reads a YAML file, or every *.yaml / *.yml file in a directory
// (sorted by name), and validates the merged result. An empty path returns
// an empty inventory.
func Load(p string) (*Inventory, error) {
	if p == "" {
		return Empty(), nil
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}

	files := []string{p}
	if info.IsDir() {
		files = nil
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, fmt.Errorf("inventory: %w", err)
		}
		for _, e := range entries {
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if !e.IsDir() && (ext == ".yaml" || ext == ".yml") {
				files = append(files, filepath.Join(p, e.Name()))
			}
		}
		sort.Strings(files)
	}

	var all []Service
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("inventory: %w", err)
		}
		doc, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("inventory %s: %w", f, err)
		}
		all = append(all, doc.Services...)
	}
	return build(all)
}

// Parse decodes one YAML document, rejecting unknown fields so typos fail
// loudly instead of silently dropping configuration.
func Parse(data []byte) (File, error) {
	var doc File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return File{}, err
	}
	return doc, nil
}

func build(services []Service) (*Inventory, error) {
	inv := &Inventory{
		services: services,
		byName:   make(map[string]*Service, len(services)),
		byDTProj: make(map[string]Match),
	}
	var errs []error
	for i := range inv.services {
		s := &inv.services[i]
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("services[%d]: name is required", i))
			continue
		}
		if _, dup := inv.byName[s.Name]; dup {
			errs = append(errs, fmt.Errorf("service %q: defined more than once", s.Name))
			continue
		}
		inv.byName[s.Name] = s

		switch s.Exposure {
		case "":
			s.Exposure = ExposureInternal
		case ExposureInternet, ExposureInternal, ExposurePrivate:
		default:
			errs = append(errs, fmt.Errorf("service %q: exposure %q: want internet, internal or private", s.Name, s.Exposure))
		}

		for j, r := range s.Repositories {
			if r.Repo == "" {
				errs = append(errs, fmt.Errorf("service %q: repositories[%d]: repo is required", s.Name, j))
				continue
			}
			for _, proj := range r.Projects() {
				if prev, dup := inv.byDTProj[proj]; dup {
					errs = append(errs, fmt.Errorf("dependency-track project %q: claimed by %s (%s) and %s (%s)",
						proj, prev.Service.Name, prev.Repository, s.Name, r.Repo))
					continue
				}
				inv.byDTProj[proj] = Match{Service: s, Repository: r.Repo}
			}
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return inv, nil
}

// LookupProject resolves a Dependency-Track project name.
func (inv *Inventory) LookupProject(name string) (Match, bool) {
	m, ok := inv.byDTProj[name]
	return m, ok
}

// Service returns a service by name.
func (inv *Inventory) Service(name string) (*Service, bool) {
	s, ok := inv.byName[name]
	return s, ok
}

// Services returns all services in definition order.
func (inv *Inventory) Services() []Service {
	return inv.services
}
