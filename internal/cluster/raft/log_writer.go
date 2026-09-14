package raft

import (
	"io"
	"strings"

	"github.com/sirupsen/logrus"
)

type raftLogWriter struct {
	entry *logrus.Entry
	level logrus.Level
}

// newRaftLogWriter returns an io.Writer that logs non-empty messages to entry at the given level.
func newRaftLogWriter(entry *logrus.Entry, level logrus.Level) io.Writer {
	if entry == nil {
		entry = logrus.NewEntry(logrus.StandardLogger())
	}
	return &raftLogWriter{entry: entry, level: level}
}

// NewRaftLogWriter is an exported constructor for newRaftLogWriter.
func NewRaftLogWriter(entry *logrus.Entry, level logrus.Level) io.Writer {
	return newRaftLogWriter(entry, level)
}

var levelTags = []struct {
	tag string
	lvl logrus.Level
}{
	{"[DEBUG]", logrus.DebugLevel},
	{"[INFO]", logrus.InfoLevel},
	{"[WARN]", logrus.WarnLevel},
	{"[ERROR]", logrus.ErrorLevel},
	{"[ERR]", logrus.ErrorLevel},
}

func (w *raftLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		lvl := w.level
		bestIdx := -1
		var bestTag string
		var matchedLvl logrus.Level

		for _, t := range levelTags {
			idx := strings.Index(msg, t.tag)
			if idx != -1 && (bestIdx == -1 || idx < bestIdx || (idx == bestIdx && len(t.tag) > len(bestTag))) {
				bestIdx = idx
				bestTag = t.tag
				matchedLvl = t.lvl
			}
		}

		if bestIdx != -1 {
			lvl = matchedLvl
			msg = strings.TrimSpace(msg[bestIdx+len(bestTag):])
		}
		w.entry.Log(lvl, msg)
	}
	return len(p), nil
}
