package scan

import (
	"path"
	"sort"
	"strings"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/stores"
)

// resolveLink follows symlinks and hard links (including directory symlinks
// on the way, as in merged-/usr layouts) and returns the final path, or ""
// when the chain is too long or loops.
func (w *walker) resolveLink(p string, hops int) string {
	if hops > maxLinkHops {
		return ""
	}
	if t, ok := w.hardlinks[p]; ok {
		return w.resolveLink(t, hops+1)
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := ""
	for i, seg := range segs {
		cur += "/" + seg
		if t, ok := w.symlinks[cur]; ok {
			rest := strings.Join(segs[i+1:], "/")
			next := t
			if rest != "" {
				next = t + "/" + rest
			}
			return w.resolveLink(absPath(next), hops+1)
		}
	}
	return p
}

// aliasIndex maps every file to the link names that resolve to it: symlinks
// and hard links, and, for the files that hold certificates, the names
// below directory symlinks (/etc/ssl/certs -> .../directory-hash makes every
// file of the hashed directory reachable as /etc/ssl/certs/<name>).
func (w *walker) aliasIndex() map[string][]string {
	index := map[string]map[string]bool{}
	add := func(link string) {
		target := w.resolveLink(link, 0)
		if target == "" || target == link {
			return
		}
		if index[target] == nil {
			index[target] = map[string]bool{}
		}
		index[target][link] = true
	}
	for link := range w.symlinks {
		add(link)
	}
	for link := range w.hardlinks {
		add(link)
	}

	// Names that may sit below a directory symlink: the stores and every
	// link name (a hash link inside a linked directory is reachable too).
	names := make([]string, 0, len(w.storeList)+len(w.symlinks)+len(w.hardlinks))
	names = append(names, w.storeList...)
	for link := range w.symlinks {
		names = append(names, link)
	}
	for link := range w.hardlinks {
		names = append(names, link)
	}
	dirs := map[string]bool{}
	for _, n := range names {
		for d := path.Dir(n); d != "/" && d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	dirLinks := map[string][]string{} // resolved directory -> symlinks to it
	for link := range w.symlinks {
		if t := w.resolveLink(link, 0); t != "" && t != link && dirs[t] {
			dirLinks[t] = append(dirLinks[t], link)
		}
	}
	if len(dirLinks) > 0 {
		for _, n := range names {
			for d := path.Dir(n); d != "/" && d != "."; d = path.Dir(d) {
				for _, link := range dirLinks[d] {
					alias := link + n[len(d):]
					target := w.resolveLink(alias, 0)
					if target == "" || target == alias {
						continue
					}
					if _, isStore := w.stores[target]; !isStore {
						continue
					}
					if index[target] == nil {
						index[target] = map[string]bool{}
					}
					index[target][alias] = true
				}
			}
		}
	}

	out := make(map[string][]string, len(index))
	for target, set := range index {
		list := make([]string, 0, len(set))
		for a := range set {
			list = append(list, a)
		}
		sort.Strings(list)
		out[target] = list
	}
	return out
}

// classRank orders store classes by how strongly they state that their
// certificates are trusted; a lower rank wins when a file is classified by
// its real path and by its aliases.
func classRank(s stores.Store) int {
	switch s.Class {
	case stores.ClassSystemBundle, stores.ClassSystemBlocklist:
		return 0
	case stores.ClassSystemAnchorDir, stores.ClassNSSDB:
		return 1
	case stores.ClassJavaKeystore, stores.ClassAppBundle:
		if s.TrustedByDefault {
			return 1
		}
		return 4
	case stores.ClassEmbeddedRuntime:
		return 2
	case stores.ClassSystemSource:
		return 3
	case stores.ClassEmbeddedBinary:
		return 5
	}
	return 6
}

// promoteStores gives every store the strongest classification over its
// real path and its aliases (a bundle reached only through a link from a
// trust-store path is that store). Among equally strong classifications a
// generated store (the distribution's bundle) is preferred, then the real
// path, then the first alias. A per-CA source file keeps its class even
// when hashed-directory links point at it: those links are products of the
// source's configuration, which decides its trust.
func (w *walker) promoteStores() {
	for _, p := range w.storeList {
		ss := w.stores[p]
		best, bestIsReal := ss.store, true
		for _, alias := range w.aliases[p] {
			st := stores.Classify(alias, ss.head)
			ra, rb := classRank(st), classRank(best)
			better := ra < rb || ra == rb && !bestIsReal && st.SystemGenerated && !best.SystemGenerated
			if !better || ss.store.Class == stores.ClassSystemSource && st.Class == stores.ClassSystemAnchorDir {
				continue
			}
			best, bestIsReal, ss.via = st, false, alias
		}
		ss.final = best
	}
}

// p11KitFamilyPrefixes are the directories whose trust stores p11-kit
// manages (RHEL/Fedora, SUSE, Arch): sources, anchors, blocklists and the
// extracted bundles and keystores generated from them. The blocklist
// directories of those trees take precedence over every other source.
var p11KitFamilyPrefixes = []string{
	"/etc/pki/ca-trust/", "/etc/pki/tls/", "/etc/pki/java/", "/usr/share/pki/ca-trust-source/", "/usr/share/pki/ca-trust-legacy/",
	"/etc/pki/trust/", "/usr/share/pki/trust/", "/var/lib/ca-certificates/", "/etc/ssl/ca-bundle.pem",
	"/etc/ca-certificates/extracted/", "/etc/ca-certificates/trust-source/", "/usr/share/ca-certificates/trust-source/",
}

// p11KitFamily reports whether the file, by its real path or one of its
// aliases, belongs to a p11-kit managed trust tree.
func p11KitFamily(p string, aliases []string) bool {
	for _, name := range append([]string{p}, aliases...) {
		for _, prefix := range p11KitFamilyPrefixes {
			if strings.HasPrefix(name, prefix) || name == strings.TrimSuffix(prefix, "/") {
				return true
			}
		}
	}
	return false
}

// blocklistName returns the real path or the alias that lies in a blocklist
// directory, if any.
func blocklistName(p string, aliases []string) (string, bool) {
	if stores.IsBlocklistPath(p) {
		return p, true
	}
	for _, a := range aliases {
		if stores.IsBlocklistPath(a) {
			return a, true
		}
	}
	return "", false
}

// distrustIndex holds the certificates that the p11-kit family distrusts:
// everything in a blocklist directory (by real path or alias) and every
// x-distrusted object of a p11-kit source, keyed by fingerprint and by
// public-key hash, with the path that distrusts them.
type distrustIndex struct {
	byFP   map[string]string
	bySPKI map[string]string
}

func (d *distrustIndex) add(id certID, source string) {
	if d.byFP == nil {
		d.byFP = map[string]string{}
		d.bySPKI = map[string]string{}
	}
	if _, ok := d.byFP[id.sha256]; !ok && id.sha256 != "" {
		d.byFP[id.sha256] = source
	}
	if _, ok := d.bySPKI[id.spki]; !ok && id.spki != "" {
		d.bySPKI[id.spki] = source
	}
}

// lookup returns the path that distrusts the certificate, matching the
// fingerprint first and then the public key.
func (d *distrustIndex) lookup(info CertInfo) (string, bool) {
	if p, ok := d.byFP[info.SHA256]; ok && info.SHA256 != "" {
		return p, true
	}
	p, ok := d.bySPKI[info.SPKISHA256]
	return p, ok && info.SPKISHA256 != ""
}

// collectDistrust builds the distrust index from the stores (after alias
// promotion) and the bundle fingerprint map used for Debian source files.
func (w *walker) collectDistrust() {
	w.bundleFP = map[string]string{}
	for _, p := range w.storeList {
		ss := w.stores[p]
		aliases := w.aliases[p]
		if name, ok := blocklistName(p, aliases); ok {
			for _, id := range ss.ids {
				w.distrust.add(id, name)
			}
		} else if p11KitFamily(p, aliases) {
			for _, id := range ss.distrusted {
				w.distrust.add(id, p)
			}
		}
		if ss.final.Class == stores.ClassSystemBundle {
			for _, id := range ss.ids {
				if _, ok := w.bundleFP[id.sha256]; !ok {
					w.bundleFP[id.sha256] = p
				}
			}
		}
	}
}

// directoryHints are the variables that name a certificate directory rather
// than a file; they only apply to OpenSSL-style stores.
var directoryHints = map[string]bool{"SSL_CERT_DIR": true, "GIT_SSL_CAPATH": true, "PERL_LWP_SSL_CA_PATH": true}

// envSelects reports which environment hint points at the file: directly,
// through an alias, or, for directory variables, as a directory containing
// it. Hint paths are resolved through links first, so SSL_CERT_FILE pointing
// at a symlinked bundle selects the real file. Directory hints never select
// keystores, NSS databases or executables, which OpenSSL does not read.
func (w *walker) envSelects(p string, aliases []string, st stores.Store) (stores.EnvHint, bool) {
	names := append([]string{p}, aliases...)
	for _, h := range w.hints {
		if h.Path == "" || h.Warning {
			continue
		}
		hp := absPath(h.Path)
		if resolved := w.resolveLink(hp, 0); resolved != "" {
			hp = resolved
		}
		if hp == p {
			return h, true
		}
		if !directoryHints[h.Variable] {
			for _, n := range names {
				if n == hp {
					return h, true
				}
			}
			continue
		}
		switch st.Class {
		case stores.ClassJavaKeystore, stores.ClassNSSDB, stores.ClassEmbeddedRuntime, stores.ClassEmbeddedBinary:
			continue
		}
		for _, n := range names {
			if strings.HasPrefix(n, hp+"/") || strings.HasPrefix(n, absPath(h.Path)+"/") {
				return h, true
			}
		}
	}
	return stores.EnvHint{}, false
}
