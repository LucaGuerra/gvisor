// Copyright 2021 The gVisor Authors.
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

package boot

import (
	"encoding/json"

	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"

	_ "gvisor.dev/gvisor/pkg/sentry/seccheck/checkers/remote"
)

func setupSeccheck(configFD int, sinkFDs []int) error {
	decoder := json.NewDecoder(fd.New(configFD))
	var session seccheck.SessionConfig
	if err := decoder.Decode(&session); err != nil {
		return err
	}
	for i, sinkFD := range sinkFDs {
		if sinkFD >= 0 {
			session.Sinks[i].FD = fd.New(sinkFD)
		}
	}
	return seccheck.Configure(&session)
}
