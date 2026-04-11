package api

import "github.com/aptly-dev/aptly/deb"

type remoteRepoResponse struct {
	*deb.RemoteRepo
	NumPackages int `json:"NumPackages"`
}

type localRepoResponse struct {
	*deb.LocalRepo
	NumPackages int `json:"NumPackages"`
}

type snapshotResponse struct {
	*deb.Snapshot
	NumPackages int `json:"NumPackages"`
}

func newRemoteRepoResponse(repo *deb.RemoteRepo) remoteRepoResponse {
	return remoteRepoResponse{RemoteRepo: repo, NumPackages: repo.NumPackages()}
}

func newLocalRepoResponse(repo *deb.LocalRepo) localRepoResponse {
	return localRepoResponse{LocalRepo: repo, NumPackages: repo.NumPackages()}
}

func newSnapshotResponse(snapshot *deb.Snapshot) snapshotResponse {
	return snapshotResponse{Snapshot: snapshot, NumPackages: snapshot.NumPackages()}
}
