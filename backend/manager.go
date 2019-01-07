// Copyright 2015 flannel authors
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

package backend

import (
	"fmt"
	"strings"
	"sync"

	"golang.org/x/net/context"

	"github.com/coreos/flannel/subnet"
)

var constructors = make(map[string]BackendCtor)

type Manager interface {
	GetBackend(backendType string) (Backend, error)
}

type manager struct {
	ctx      context.Context
	sm       subnet.Manager
	extIface *ExternalInterface
	mux      sync.Mutex
	active   map[string]Backend
	wg       sync.WaitGroup
}

func NewManager(ctx context.Context, sm subnet.Manager, extIface *ExternalInterface) Manager {
	return &manager{
		ctx:      ctx,
		sm:       sm,
		extIface: extIface,
		active:   make(map[string]Backend),
	}
}

/**
 * 获取Backend对象
 * @param  backendType 类型
 * @return Backend对象
 */
func (bm *manager) GetBackend(backendType string) (Backend, error) {
	bm.mux.Lock()
	defer bm.mux.Unlock()
	// betype 一般是udp、vxlan、hostgw
	betype := strings.ToLower(backendType)
	// see if one is already running 表示已经存在backend
	if be, ok := bm.active[betype]; ok {
		return be, nil
	}

	// first request, need to create and run it
	// 假设betype为vxlan则befunc为vxlan.go文件下的New函数
	befunc, ok := constructors[betype]
	if !ok {
		return nil, fmt.Errorf("unknown backend type: %v", betype)
	}

	be, err := befunc(bm.sm, bm.extIface) // befunc实际指向New函数
	if err != nil {
		return nil, err
	}
	bm.active[betype] = be //设置缓存

	//设置同步 并 启动协程 等待context结束操作
	bm.wg.Add(1)
	go func() {
		<-bm.ctx.Done() //阻塞在这里

		// TODO(eyakubovich): this obviosly introduces a race.
		// GetBackend() could get called while we are here.
		// Currently though, all backends' Run exit only
		// on shutdown

		bm.mux.Lock()
		delete(bm.active, betype)
		bm.mux.Unlock()

		bm.wg.Done()
	}()

	return be, nil
}

// 该函数调用 大部分都是在init函数中
func Register(name string, ctor BackendCtor) {
	constructors[name] = ctor
}
