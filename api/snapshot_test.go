package api

import (
	"bytes"
	"encoding/json"

	"github.com/gin-gonic/gin"
	. "gopkg.in/check.v1"
)

type SnapshotsSuite struct {
	APISuite
}

var _ = Suite(&SnapshotsSuite{})

func (s *SnapshotsSuite) TestGetSnapshotsIncludesNumPackages(c *C) {
	body, err := json.Marshal(gin.H{"Name": "count-snapshot-list"})
	c.Assert(err, IsNil)

	response, err := s.HTTPRequest("POST", "/api/snapshots", bytes.NewReader(body))
	c.Assert(err, IsNil)
	c.Assert(response.Code, Equals, 201)

	response, err = s.HTTPRequest("GET", "/api/snapshots", nil)
	c.Assert(err, IsNil)
	c.Assert(response.Code, Equals, 200)

	var snapshots []map[string]interface{}
	err = json.Unmarshal(response.Body.Bytes(), &snapshots)
	c.Assert(err, IsNil)

	found := false
	for _, snapshot := range snapshots {
		if snapshot["Name"] == "count-snapshot-list" {
			found = true
			value, ok := snapshot["NumPackages"]
			c.Assert(ok, Equals, true)
			c.Assert(value, Equals, float64(0))
			break
		}
	}

	c.Assert(found, Equals, true)
}
