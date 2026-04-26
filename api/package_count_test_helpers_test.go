package api

import (
	"github.com/aptly-dev/aptly/deb"
	. "gopkg.in/check.v1"
)

func makePackageRefList(c *C) *deb.PackageRefList {
	list := deb.NewPackageList()
	c.Assert(list.Add(&deb.Package{Name: "libcount", Version: "1.0", Architecture: "amd64"}), IsNil)
	c.Assert(list.Add(&deb.Package{Name: "appcount", Version: "2.0", Architecture: "all"}), IsNil)
	return deb.NewPackageRefListFromPackageList(list)
}

func putRawDBValue(c *C, s *APISuite, key []byte, value []byte) {
	db, err := s.context.Database()
	c.Assert(err, IsNil)
	c.Assert(db.Put(key, value), IsNil)
}