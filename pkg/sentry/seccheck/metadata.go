// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package seccheck

import (
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/fd"
)

// PointX represents the checkpoint X.
const (
	PointClone Point = iota
	PointExecve
	PointExitNotifyParent
	PointContainerStart

	// Add new Points above this line.
	pointLengthBeforeSyscalls
)

const (
	FieldCommonCredentials Field = iota

	FieldCommonTaskThreadID
	FieldCommonTaskStartTime
	FieldCommonTaskGroupID
	FieldCommonTaskThreadGroupStartTime
	FieldCommonTaskContainerID
)

const (
	ContainerStartFieldEnv Field = iota
)

var Points = map[string]PointDesc{}
var Sinks = map[string]SinkDesc{}

var defaultContextFields = []FieldDesc{
	{
		ID:   FieldCommonCredentials,
		Name: "credentials",
	},
	{
		ID:   FieldCommonTaskThreadID,
		Name: "thread_id",
	},
	{
		ID:   FieldCommonTaskStartTime,
		Name: "task_start_time",
	},
	{
		ID:   FieldCommonTaskGroupID,
		Name: "group_id",
	},
	{
		ID:   FieldCommonTaskThreadGroupStartTime,
		Name: "thread_group_start_time",
	},
	{
		ID:   FieldCommonTaskContainerID,
		Name: "container_id",
	},
}

type SinkDesc struct {
	Name  string
	Setup func(config map[string]interface{}) (*os.File, error)
	New   func(config map[string]interface{}, endpoint *fd.FD) (Checker, error)
}

func RegisterSink(sink SinkDesc) {
	if _, ok := Sinks[sink.Name]; ok {
		panic(fmt.Sprintf("Sink %q already registered", sink.Name))
	}
	Sinks[sink.Name] = sink
}

type PointDesc struct {
	ID             Point
	Name           string
	OptionalFields []FieldDesc
	ContextFields  []FieldDesc
}

type FieldDesc struct {
	ID   Field
	Name string
}

func registerPoint(pt PointDesc) {
	if _, ok := Points[pt.Name]; ok {
		panic(fmt.Sprintf("Point %q already registered", pt.Name))
	}
	Points[pt.Name] = pt
}

func addRawSyscallPoint(sysno uintptr) {
	addSyscallPointHelper(SyscallRawEnter, sysno, fmt.Sprintf("%d", sysno), nil)
}

func addSyscallPoint(sysno uintptr, name string, optionalFields []FieldDesc) {
	addSyscallPointHelper(SyscallEnter, sysno, name, optionalFields)
}

func addSyscallPointHelper(typ SyscallType, sysno uintptr, name string, optionalFields []FieldDesc) {
	registerPoint(PointDesc{
		ID:             GetPointForSyscall(typ, sysno),
		Name:           "syscall/" + name + "/enter",
		OptionalFields: optionalFields,
		ContextFields:  defaultContextFields,
	})
	registerPoint(PointDesc{
		ID:             GetPointForSyscall(typ+1, sysno),
		Name:           "syscall/" + name + "/exit",
		OptionalFields: optionalFields,
		ContextFields:  defaultContextFields,
	})
}

func init() {
	registerPoint(PointDesc{
		ID:            PointClone,
		Name:          "sentry/clone",
		ContextFields: defaultContextFields,
	})
	registerPoint(PointDesc{
		ID:   PointExecve,
		Name: "sentry/execve",
		OptionalFields: []FieldDesc{
			{
				ID:   ExecveFieldBinaryInfo,
				Name: "binary_info",
			},
		},
		ContextFields: defaultContextFields,
	})
	registerPoint(PointDesc{
		ID:            PointExitNotifyParent,
		Name:          "sentry/exit_notify_parent",
		ContextFields: defaultContextFields,
	})
	registerPoint(PointDesc{
		ID:   PointContainerStart,
		Name: "container/start",
		OptionalFields: []FieldDesc{
			{
				ID:   ContainerStartFieldEnv,
				Name: "env",
			},
		},
		ContextFields: defaultContextFields,
	})
}