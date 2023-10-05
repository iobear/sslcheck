package logmodule

import (
	"fmt"
	"log"
	"os"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	ERROR
	CRITICAL
)

type Logger struct {
	level LogLevel
}

func NewLogger(level LogLevel) *Logger {
	return &Logger{level: level}
}

func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level <= DEBUG {
		log.Output(2, "[DEBUG] "+fmt.Sprintf(format, v...))
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	if l.level <= INFO {
		log.Output(2, "[INFO] "+fmt.Sprintf(format, v...))
	}
}

func (l *Logger) Error(format string, v ...interface{}) {
	if l.level <= ERROR {
		log.Output(2, "[ERROR] "+fmt.Sprintf(format, v...))
	}
}

func (l *Logger) Critical(format string, v ...interface{}) {
	if l.level <= CRITICAL {
		log.Output(2, "[CRITICAL] "+fmt.Sprintf(format, v...))
		os.Exit(1) // Exit on critical logs.
	}
}
