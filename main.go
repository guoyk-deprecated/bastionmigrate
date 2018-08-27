package main

import (
	"flag"
	"github.com/asdine/storm"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yankeguo/bastion/daemon"
	newModels "github.com/yankeguo/bastion/daemon/models"
	newTypes "github.com/yankeguo/bastion/types"
	oldModels "github.com/yankeguo/bunker/models"
	oldTypes "github.com/yankeguo/bunker/types"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

var (
	dbIn       string
	replaysIn  string
	dbOut      string
	replaysOut string
)

func main() {
	var err error

	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})

	flag.StringVar(&dbIn, "db-in", "database.sqlite3", "input bunker sqlite db")
	flag.StringVar(&replaysIn, "replays-in", "bunker-replays", "input bunker replays directory")
	flag.StringVar(&dbOut, "db-out", "database.bolt", "output bastion bolt db")
	flag.StringVar(&replaysOut, "replays-out", "bastion-replays", "output bastion replays directory")
	flag.Parse()

	var oldDB *oldModels.DB
	if oldDB, err = oldModels.NewDB(oldTypes.Config{DB: oldTypes.DBConfig{File: dbIn}}); err != nil {
		panic(err)
	}
	defer oldDB.Close()

	var newDB *storm.DB
	if newDB, err = storm.Open(dbOut); err != nil {
		panic(err)
	}
	defer newDB.Close()

	// users
	oldUsers := []oldModels.User{}
	if err = oldDB.Find(&oldUsers).Error; err != nil {
		panic(err)
	}
	for _, oldUser := range oldUsers {
		newUser := newModels.User{}
		newUser.Account = oldUser.Account
		newUser.PasswordDigest = oldUser.PasswordDigest
		newUser.Nickname = oldUser.Account
		newUser.IsBlocked = oldUser.IsBlocked != 0
		newUser.IsAdmin = oldUser.IsAdmin != 0
		newUser.CreatedAt = oldUser.CreatedAt.Unix()
		newUser.UpdatedAt = oldUser.UpdatedAt.Unix()
		if oldUser.UsedAt != nil {
			newUser.ViewedAt = oldUser.UsedAt.Unix()
		}
		if err = newDB.Save(&newUser); err != nil {
			log.Error().Interface("user", newUser).Err(err).Msg("failed to import user")
			panic(err)
		} else {
			log.Info().Interface("user", newUser).Msg("user imported")
		}
	}

	// keys
	oldKeys := []oldModels.Key{}
	if err = oldDB.Find(&oldKeys).Error; err != nil {
		panic(err)
	}
	for _, oldKey := range oldKeys {
		newKey := newModels.Key{}
		newKey.Fingerprint = oldKey.Fingerprint
		for _, oldUser := range oldUsers {
			if oldKey.UserID == oldUser.ID {
				newKey.Account = oldUser.Account
				break
			}
		}
		if len(newKey.Account) == 0 {
			panic(errors.New("missing user for key" + oldKey.Fingerprint))
		}
		if oldKey.IsSandbox != 0 {
			newKey.Source = newTypes.KeySourceSandbox
		} else {
			newKey.Source = newTypes.KeySourceManual
		}
		newKey.Name = oldKey.Name
		newKey.CreatedAt = oldKey.CreatedAt.Unix()
		if oldKey.UsedAt != nil {
			newKey.ViewedAt = oldKey.UsedAt.Unix()
		}
		if err = newDB.Save(&newKey); err != nil {
			log.Error().Interface("key", newKey).Err(err).Msg("failed to import key")
			panic(err)
		} else {
			log.Info().Interface("key", newKey).Msg("key imported")
		}
	}

	// nodes
	oldNodes := []oldModels.Server{}
	if err = oldDB.Find(&oldNodes).Error; err != nil {
		panic(err)
	}
	for _, oldNode := range oldNodes {
		newNode := newModels.Node{}
		newNode.Hostname = oldNode.Name
		newNode.Address = oldNode.Address
		newNode.CreatedAt = oldNode.CreatedAt.Unix()
		newNode.User = newTypes.NodeUserRoot
		if oldNode.IsAuto != 0 {
			newNode.Source = newTypes.NodeSourceConsul
		} else {
			newNode.Source = newTypes.NodeSourceManual
		}
		if oldNode.UsedAt != nil {
			newNode.ViewedAt = oldNode.UsedAt.Unix()
		}
		if err = newDB.Save(&newNode); err != nil {
			log.Error().Interface("node", newNode).Err(err).Msg("failed to import node")
			panic(err)
		} else {
			log.Info().Interface("node", newNode).Msg("node imported")
		}
	}

	// grants
	oldGrants := []oldModels.Grant{}
	if err = oldDB.Find(&oldGrants).Error; err != nil {
		panic(err)
	}
	for _, oldGrant := range oldGrants {
		newGrant := newModels.Grant{}
		for _, oldUser := range oldUsers {
			if oldGrant.UserID == oldUser.ID {
				newGrant.Account = oldUser.Account
				break
			}
		}
		if len(newGrant.Account) == 0 {
			panic(errors.New("missing user for grant"))
		}
		newGrant.HostnamePattern = oldGrant.ServerName
		newGrant.User = oldGrant.TargetUser
		newGrant.Id = newGrant.BuildId()
		newGrant.CreatedAt = oldGrant.CreatedAt.Unix()
		if oldGrant.ExpiresAt != nil {
			newGrant.ExpiredAt = oldGrant.ExpiresAt.Unix()
		}
		if err = newDB.Save(&newGrant); err != nil {
			log.Error().Interface("grant", newGrant).Err(err).Msg("failed to import grant")
			panic(err)
		} else {
			log.Info().Interface("grant", newGrant).Msg("grant imported")
		}
	}

	// sessions
	oldSessions := []oldModels.Session{}
	if err = oldDB.Find(&oldSessions).Error; err != nil {
		panic(err)
	}
	for _, oldSession := range oldSessions {
		newSession := newModels.Session{}
		newSession.Id = int64(oldSession.ID)
		newSession.Account = oldSession.UserAccount
		newSession.Command = oldSession.Command
		newSession.CreatedAt = oldSession.CreatedAt.Unix()
		if oldSession.EndedAt != nil {
			newSession.FinishedAt = oldSession.EndedAt.Unix()
		}
		newSession.IsRecorded = oldSession.IsRecorded != 0
		if err = newDB.Save(&newSession); err != nil {
			log.Error().Interface("session", newSession).Err(err).Msg("failed to import session")
			panic(err)
		} else {
			log.Info().Interface("session", newSession).Msg("grant imported")
		}
	}

	// replay files
	var files []string
	if files, err = filepath.Glob(replaysIn + "/*/*/*/*"); err != nil {
		panic(err)
	}
	for _, file := range files {
		var id int64
		if id, err = strconv.ParseInt(filepath.Base(file), 16, 64); err != nil {
			log.Error().Str("oldFile", file).Err(err).Msg("failed to calculate id")
			panic(err)
		}
		newFile := daemon.FilenameForSessionID(id, replaysOut)
		if err = os.MkdirAll(filepath.Dir(newFile), 0750); err != nil {
			log.Error().Str("file", newFile).Err(err).Msg("failed to create directory")
			panic(err)
		}
		if err = CopyFile(file, newFile); err != nil {
			log.Error().Str("file", newFile).Err(err).Str("oldFile", file).Msg("failed to link files")
			panic(err)
		}
		log.Info().Str("file", newFile).Str("oldFile", file).Msg("file copied")
	}
}

func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}
