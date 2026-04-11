package api

import (
	"bytes"
	"encoding/json"

	"github.com/gin-gonic/gin"
	. "gopkg.in/check.v1"
)

type ReposSuite struct {
	APISuite
}

var _ = Suite(&ReposSuite{})

func (s *ReposSuite) TestGetReposIncludesNumPackages(c *C) {
	body, err := json.Marshal(gin.H{"Name": "count-repo-list"})
	c.Assert(err, IsNil)

	response, err := s.HTTPRequest("POST", "/api/repos", bytes.NewReader(body))
	c.Assert(err, IsNil)
	c.Assert(response.Code, Equals, 201)

	response, err = s.HTTPRequest("GET", "/api/repos", nil)
	c.Assert(err, IsNil)
	c.Assert(response.Code, Equals, 200)

	var repos []map[string]interface{}
	err = json.Unmarshal(response.Body.Bytes(), &repos)
	c.Assert(err, IsNil)

	found := false
	for _, repo := range repos {
		if repo["Name"] == "count-repo-list" {
			found = true
			value, ok := repo["NumPackages"]
			c.Assert(ok, Equals, true)
			c.Assert(value, Equals, float64(0))
			break
		}
	}

	c.Assert(found, Equals, true)
}
