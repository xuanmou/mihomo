//go:build linux || darwin

package tun

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// Linux and Darwin keep sing-tun's TCP/IP stack, but feed it through the
// existing metacubex TUN Read/Write path. The upstream queue implementation
// needs TUN internals this fork does not have.
const goEngineTransmits = false

const goFallbackQueueLimit = 32

type goFallbackIO struct {
	stack   *Go
	tun     Tun
	linkMTU int
	mu      sync.Mutex
	cond    *sync.Cond
	queue   []*buf.Buffer
	closed  bool
	wakeCh  chan struct{}
	done    chan struct{}
	readErr atomic.Value
	pending []*buf.Buffer
	handed  []*buf.Buffer
	timer   *time.Timer
	once    sync.Once
}

func newGoPlatformQueues(stack *Go) ([]goPlatformIO, error) {
	queue := &goFallbackIO{
		stack:   stack,
		tun:     stack.tun,
		linkMTU: int(stack.mtu),
		wakeCh:  make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	queue.cond = sync.NewCond(&queue.mu)
	return []goPlatformIO{queue}, nil
}

func (o *goFallbackIO) start() error {
	o.once.Do(func() {
		go o.readLoop()
	})
	return nil
}

func (o *goFallbackIO) readLoop() {
	if linuxTUN, ok := o.tun.(LinuxTUN); ok && linuxTUN.FrontHeadroom() > 0 {
		o.readLoopOffload(linuxTUN)
		return
	}
	size := o.linkMTU + PacketOffset
	if size < 2048 {
		size = 65535
	}
	scratch := make([]byte, size)
	for {
		n, err := o.tun.Read(scratch)
		if n > PacketOffset && !o.deliverCopied(scratch[PacketOffset:n]) {
			return
		}
		if err != nil {
			o.failRead(err)
			return
		}
	}
}

// readLoopOffload splits virtio GRO packets. Read only has one output buffer,
// so a multi-segment packet returns ErrTooManySegments and used to stop the loop.
func (o *goFallbackIO) readLoopOffload(linuxTUN LinuxTUN) {
	offset := linuxTUN.FrontHeadroom()
	batchSize := linuxTUN.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	capacity := o.linkMTU
	if capacity < 1 {
		capacity = int(gsoMaxSize)
	}
	buffers := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, offset+capacity)
	}
	for {
		n, err := linuxTUN.BatchRead(buffers, offset, sizes)
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 {
				continue
			}
			end := offset + sizes[i]
			if end > len(buffers[i]) {
				continue
			}
			if !o.deliverCopied(buffers[i][offset:end]) {
				return
			}
		}
		if err == nil {
			continue
		}
		// The packet has already been taken out of the device. Keep reading.
		if errors.Is(err, ErrTooManySegments) {
			o.logRead(err)
			continue
		}
		o.failRead(err)
		return
	}
}

func (o *goFallbackIO) deliverCopied(packet []byte) bool {
	buffer := buf.NewSize(len(packet))
	_, _ = buffer.Write(packet)
	if o.deliver(buffer) {
		return true
	}
	buffer.Release()
	return false
}

func (o *goFallbackIO) failRead(err error) {
	o.readErr.Store(err)
	o.wake()
}

func (o *goFallbackIO) logRead(err error) {
	if o.stack != nil && o.stack.logger != nil {
		o.stack.logger.Debug(E.Cause(err, "go: read packet"))
	}
}

func (o *goFallbackIO) takeError() error {
	err, _ := o.readErr.Load().(error)
	return err
}

func (o *goFallbackIO) wait(timeout time.Duration, _ []goSocketEvent) (bool, int, error) {
	if len(o.pending) > 0 || o.pull(1) {
		return true, 0, nil
	}
	if err := o.closedError(); err != nil {
		return false, 0, err
	}
	if timeout == 0 {
		return false, 0, o.takeError()
	}
	var timer <-chan time.Time
	if timeout > 0 {
		if o.timer == nil {
			o.timer = time.NewTimer(timeout)
		} else {
			o.timer.Reset(timeout)
		}
		defer o.timer.Stop()
		timer = o.timer.C
	}
	select {
	case <-o.wakeCh:
	case <-o.done:
		return false, 0, os.ErrClosed
	case <-timer:
	}
	if o.pull(1) {
		return true, 0, nil
	}
	if err := o.closedError(); err != nil {
		return false, 0, err
	}
	return false, 0, o.takeError()
}

func (o *goFallbackIO) readBurst(frames []goFrame, options N.ReadWaitOptions) (int, bool, error) {
	o.releaseReadBuffers()
	o.drainPending(frames, options)
	count := len(o.handed)
	if count == 0 {
		if err := o.takeError(); err != nil {
			return 0, false, err
		}
		if err := o.closedError(); err != nil {
			return 0, false, err
		}
	}
	drained := len(o.pending) == 0 && o.queued() == 0
	return count, drained, nil
}

func (o *goFallbackIO) drainPending(frames []goFrame, options N.ReadWaitOptions) {
	if len(o.pending) < len(frames) {
		o.pending = append(o.pending, o.pop(len(frames)-len(o.pending))...)
	}
	count := 0
	for count < len(frames) && count < len(o.pending) {
		buffer := o.pending[count]
		if options.NeedHeadroom() {
			buffer = options.Copy(buffer)
		}
		options.PostReturn(buffer)
		o.handed = append(o.handed, buffer)
		frames[count] = goFrame{buffer: buffer}
		count++
	}
	o.pending = o.pending[count:]
}

func (o *goFallbackIO) releaseReadBuffers() {
	buf.ReleaseMulti(o.handed)
	o.handed = o.handed[:0]
}

func (o *goFallbackIO) writeSegments(segments [][]byte) error {
	length := 0
	for _, segment := range segments {
		length += len(segment)
	}
	packet := make([]byte, 0, length)
	for _, segment := range segments {
		packet = append(packet, segment...)
	}
	_, err := o.tun.Write(frameOutbound(o.tun, packet))
	if err != nil {
		return err
	}
	return nil
}

func (o *goFallbackIO) writeFrame(frame [][]byte, _ ForwardFrameMeta) error {
	return o.writeSegments(frame)
}

func (o *goFallbackIO) writePacket(packet []byte, _ ForwardFrameMeta) error {
	return o.writeSegments([][]byte{packet})
}

func (o *goFallbackIO) writeDatagram(packet []byte, meta ForwardFrameMeta) error {
	return o.writePacket(packet, meta)
}

func (o *goFallbackIO) writeData(frame [][]byte, _ ForwardFrameMeta, _ *GoConn, _ uint64) error {
	return o.writeSegments(frame)
}

func (o *goFallbackIO) writePacketBatch(frames []goUDPFrame) error {
	var writeErr error
	for index := range frames {
		frame := &frames[index]
		writeErr = E.Errors(writeErr, o.writeSegments([][]byte{frame.header[:frame.length], frame.payload}))
	}
	return writeErr
}

func (o *goFallbackIO) registerSocket(*goSocket, uint32, uint8) error { return nil }
func (o *goFallbackIO) updateSocket(*goSocket, uint8) error           { return nil }
func (o *goFallbackIO) unregisterSocket(*goSocket)                    {}
func (o *goFallbackIO) transmitBacklogBelowBatch(*GoConn) bool        { return true }
func (o *goFallbackIO) flush()                                        {}
func (o *goFallbackIO) mtu() int                                      { return o.linkMTU }
func (o *goFallbackIO) supportsSockets() bool                         { return false }
func (o *goFallbackIO) transmitPrefix() int                           { return 0 }
func (o *goFallbackIO) transmitChecksumOffload() bool                 { return false }
func (o *goFallbackIO) transmitSegmentOffload() bool                  { return false }
func (o *goFallbackIO) armTransmitWritable(*GoConn) (*goBlockedWriters, error) {
	return nil, nil
}
func (o *goFallbackIO) takeTransmitWritable(writable []*goBlockedWriters) []*goBlockedWriters {
	return writable
}

func (o *goFallbackIO) wake() {
	select {
	case o.wakeCh <- struct{}{}:
	default:
	}
}

func (o *goFallbackIO) deliver(buffer *buf.Buffer) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for len(o.queue) >= goFallbackQueueLimit && !o.closed {
		o.cond.Wait()
	}
	if o.closed {
		return false
	}
	o.queue = append(o.queue, buffer)
	o.wake()
	return true
}

func (o *goFallbackIO) pop(limit int) []*buf.Buffer {
	o.mu.Lock()
	defer o.mu.Unlock()
	count := min(limit, len(o.queue))
	if count == 0 {
		return nil
	}
	buffers := append([]*buf.Buffer(nil), o.queue[:count]...)
	o.queue = append([]*buf.Buffer(nil), o.queue[count:]...)
	if len(o.queue) < goFallbackQueueLimit {
		o.cond.Signal()
	}
	return buffers
}

func (o *goFallbackIO) pull(limit int) bool {
	buffers := o.pop(limit)
	if len(buffers) == 0 {
		return false
	}
	o.pending = append(o.pending, buffers...)
	return true
}

func (o *goFallbackIO) queued() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.queue)
}

func (o *goFallbackIO) closedError() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return os.ErrClosed
	}
	return nil
}

func (o *goFallbackIO) close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	close(o.done)
	buf.ReleaseMulti(o.queue)
	o.queue = nil
	buf.ReleaseMulti(o.pending)
	o.pending = nil
	buf.ReleaseMulti(o.handed)
	o.handed = nil
	o.cond.Broadcast()
	return nil
}
