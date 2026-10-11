//go:build linux || darwin

package tun

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func TestGoFallbackCloseReleasesQueuedPackets(t *testing.T) {
	queue := newTestFallbackIO()
	buffer := buf.NewSize(4)
	_, _ = buffer.Write([]byte{1, 2, 3, 4})
	if !queue.deliver(buffer) {
		t.Fatal("deliver")
	}
	if err := queue.close(); err != nil {
		t.Fatal(err)
	}
	if buffer.Len() != 0 {
		t.Fatal("queued packet was not released")
	}
	late := buf.NewSize(1)
	_, _ = late.Write([]byte{9})
	if queue.deliver(late) {
		t.Fatal("deliver succeeded after close")
	}
	late.Release()
}

func TestGoFallbackCloseUnblocksFullQueue(t *testing.T) {
	queue := newTestFallbackIO()
	for range goFallbackQueueLimit {
		buffer := buf.NewSize(1)
		_, _ = buffer.Write([]byte{1})
		if !queue.deliver(buffer) {
			t.Fatal("fill")
		}
	}
	delivered := make(chan bool, 1)
	go func() {
		buffer := buf.NewSize(1)
		_, _ = buffer.Write([]byte{9})
		ok := queue.deliver(buffer)
		if !ok {
			buffer.Release()
		}
		delivered <- ok
	}()
	time.Sleep(50 * time.Millisecond)
	if err := queue.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-delivered:
		if ok {
			t.Fatal("accepted a packet after close")
		}
	case <-time.After(time.Second):
		t.Fatal("deliver stayed blocked on a full queue")
	}
}

func TestGoFallbackIndefiniteWaitWakes(t *testing.T) {
	queue := newTestFallbackIO()
	started := time.Now()
	go func() {
		time.Sleep(30 * time.Millisecond)
		queue.wake()
	}()
	readable, _, err := queue.wait(-1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if readable {
		t.Fatal("woke with a packet")
	}
	elapsed := time.Since(started)
	if elapsed < 20*time.Millisecond || elapsed > time.Second {
		t.Fatalf("wait returned after %s", elapsed)
	}
}

func TestGoFallbackReadErrorWakesWaiter(t *testing.T) {
	queue := newTestFallbackIO()
	go queue.readLoop()
	readable, _, err := queue.wait(time.Second, nil)
	if readable || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("readable=%v err=%v", readable, err)
	}
}

func TestGoFallbackOffloadContinuesAfterTooManySegments(t *testing.T) {
	device := &scriptLinuxTun{
		headroom:  12,
		batchSize: 4,
		reads: []scriptRead{
			{packets: [][]byte{{0x45, 0, 0, 1}}, err: ErrTooManySegments},
			{packets: [][]byte{{0x45, 0, 0, 2}}},
			{err: os.ErrClosed},
		},
	}
	queue := newTestFallbackIO()
	queue.tun = device
	queue.linkMTU = 1500
	go queue.readLoop()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && queue.takeError() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	if !errors.Is(queue.takeError(), os.ErrClosed) {
		t.Fatalf("read error = %v", queue.takeError())
	}
	if queue.queued() != 2 {
		t.Fatalf("queued %d packets", queue.queued())
	}
}

func newTestFallbackIO() *goFallbackIO {
	queue := &goFallbackIO{
		linkMTU: 1500,
		tun:     idleTun{},
		wakeCh:  make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	queue.cond = sync.NewCond(&queue.mu)
	return queue
}

type scriptRead struct {
	packets [][]byte
	err     error
}

type scriptLinuxTun struct {
	headroom  int
	batchSize int
	reads     []scriptRead
	index     int
}

func (t *scriptLinuxTun) Read([]byte) (int, error)         { return 0, os.ErrClosed }
func (t *scriptLinuxTun) Write(packet []byte) (int, error) { return len(packet), nil }
func (t *scriptLinuxTun) Close() error                     { return nil }
func (t *scriptLinuxTun) FrontHeadroom() int               { return t.headroom }
func (t *scriptLinuxTun) BatchSize() int                   { return t.batchSize }
func (t *scriptLinuxTun) TXChecksumOffload() bool          { return false }
func (t *scriptLinuxTun) BatchWrite([][]byte, int) (int, error) {
	return 0, nil
}
func (t *scriptLinuxTun) BatchRead(buffers [][]byte, offset int, sizes []int) (int, error) {
	if t.index >= len(t.reads) {
		return 0, os.ErrClosed
	}
	read := t.reads[t.index]
	t.index++
	count := 0
	for _, packet := range read.packets {
		if count >= len(buffers) || offset+len(packet) > len(buffers[count]) {
			return count, ErrTooManySegments
		}
		copy(buffers[count][offset:offset+len(packet)], packet)
		sizes[count] = len(packet)
		count++
	}
	return count, read.err
}

type idleTun struct{}

func (idleTun) Read([]byte) (int, error) { return 0, os.ErrClosed }
func (idleTun) Write(packet []byte) (int, error) {
	return len(packet), nil
}
func (idleTun) Close() error { return nil }
