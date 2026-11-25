package peer

import (
	"context"
	"sync"
	"time"

	"github.com/pion/webrtc/v5"
)

const (
	bufferedAmountLowThreshold  = 256 * 1024
	bufferedAmountHighThreshold = 512 * 1024
)

type outboundChunk struct {
	data []byte
}

// managedChannel wraps a WebRTC DataChannel with a bounded outbound queue,
// BufferedAmount backpressure, negotiated message-size limits, and path-verification gating.
type managedChannel struct {
	label        string
	maxMsgBytes  int
	maxQueueByte int

	mu          sync.Mutex
	dc          *webrtc.DataChannel
	dcOpen      bool
	pathAllowed bool
	closed      bool
	queue       []outboundChunk
	queuedBytes int
	notifyCh    chan struct{}

	onMessage func([]byte)
}

func newManagedChannel(label string, maxMsgBytes, maxQueueBytes int, onMessage func([]byte)) *managedChannel {
	if maxMsgBytes <= 0 || maxMsgBytes > MaxApplicationMessageBytes {
		maxMsgBytes = MaxApplicationMessageBytes
	}
	if maxQueueBytes <= 0 {
		maxQueueBytes = DefaultApplicationQueueBytes
	}
	mc := &managedChannel{
		label:        label,
		maxMsgBytes:  maxMsgBytes,
		maxQueueByte: maxQueueBytes,
		notifyCh:     make(chan struct{}, 1),
		onMessage:    onMessage,
	}
	go mc.flushLoop()
	return mc
}

func (mc *managedChannel) bindDataChannel(dc *webrtc.DataChannel, maxMsgBytes int) {
	dc.SetBufferedAmountLowThreshold(bufferedAmountLowThreshold)

	mc.mu.Lock()
	if maxMsgBytes > 0 && maxMsgBytes < mc.maxMsgBytes {
		mc.maxMsgBytes = maxMsgBytes
	}
	mc.dc = dc
	mc.dcOpen = dc.ReadyState() == webrtc.DataChannelStateOpen
	mc.mu.Unlock()
	mc.signal()

	dc.OnOpen(func() {
		mc.mu.Lock()
		if mc.dc == dc {
			mc.dcOpen = true
		}
		mc.mu.Unlock()
		mc.signal()
	})

	dc.OnBufferedAmountLow(func() {
		mc.signal()
	})

	dc.OnClose(func() {
		mc.mu.Lock()
		if mc.dc == dc {
			mc.dcOpen = false
		}
		mc.mu.Unlock()
		mc.signal()
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		mc.mu.Lock()
		allowed := mc.pathAllowed && !mc.closed && mc.dc == dc
		limit := mc.maxMsgBytes
		mc.mu.Unlock()
		if !allowed {
			return
		}
		if len(msg.Data) > limit {
			_ = dc.Close()
			return
		}
		if mc.onMessage != nil {
			cp := make([]byte, len(msg.Data))
			copy(cp, msg.Data)
			mc.onMessage(cp)
		}
	})
}

func (mc *managedChannel) isBound() bool {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return mc.dc != nil && !mc.closed
}

func (mc *managedChannel) setPathAllowed(allowed bool) {
	mc.mu.Lock()
	mc.pathAllowed = allowed
	mc.mu.Unlock()
	mc.signal()
}

func (mc *managedChannel) close() {
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return
	}
	mc.closed = true
	mc.pathAllowed = false
	dc := mc.dc
	mc.queue = nil
	mc.queuedBytes = 0
	mc.mu.Unlock()

	mc.signal()
	if dc != nil {
		_ = dc.Close()
	}
}

func (mc *managedChannel) enqueue(ctx context.Context, payload []byte) error {
	mc.mu.Lock()
	limit := mc.maxMsgBytes
	mc.mu.Unlock()
	if len(payload) > limit {
		return ErrMessageTooLarge
	}

	cp := make([]byte, len(payload))
	copy(cp, payload)

	for {
		mc.mu.Lock()
		if mc.closed {
			mc.mu.Unlock()
			return ErrSessionClosed
		}
		var dcBuffered int
		dcReady := mc.dcOpen
		if mc.dc != nil {
			dcBuffered = int(mc.dc.BufferedAmount())
			if !dcReady && mc.dc.ReadyState() == webrtc.DataChannelStateOpen {
				dcReady = true
				mc.dcOpen = true
			}
		}
		canFit := mc.pathAllowed && dcReady && (mc.queuedBytes+dcBuffered+len(cp) <= mc.maxQueueByte)
		if canFit {
			mc.queue = append(mc.queue, outboundChunk{data: cp})
			mc.queuedBytes += len(cp)
			mc.mu.Unlock()
			mc.signal()
			return nil
		}
		waitingForOpen := mc.pathAllowed && mc.dc != nil && !dcReady
		mc.mu.Unlock()

		if waitingForOpen {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-mc.notifyCh:
			case <-time.After(15 * time.Millisecond):
			}
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-mc.notifyCh:
		}
	}
}

func (mc *managedChannel) flushLoop() {
	for {
		mc.mu.Lock()
		if mc.closed {
			mc.mu.Unlock()
			return
		}
		dcReady := mc.dcOpen
		if mc.dc != nil && !dcReady && mc.dc.ReadyState() == webrtc.DataChannelStateOpen {
			dcReady = true
			mc.dcOpen = true
		}
		if !mc.pathAllowed || !dcReady || mc.dc == nil || len(mc.queue) == 0 ||
			mc.dc.BufferedAmount() >= bufferedAmountHighThreshold {
			needPoll := mc.pathAllowed && mc.dc != nil && !dcReady && len(mc.queue) > 0
			mc.mu.Unlock()
			if needPoll {
				select {
				case <-mc.notifyCh:
				case <-time.After(15 * time.Millisecond):
				}
			} else {
				<-mc.notifyCh
			}
			continue
		}

		dc := mc.dc
		item := mc.queue[0]
		mc.queue = mc.queue[1:]
		mc.queuedBytes -= len(item.data)
		mc.mu.Unlock()

		if err := dc.Send(item.data); err != nil {
			// Re-queue at head if path is switching/reconnecting and channel hasn't permanently closed.
			mc.mu.Lock()
			if !mc.closed && mc.dc == dc {
				mc.dcOpen = false
			}
			if !mc.closed {
				mc.queue = append([]outboundChunk{item}, mc.queue...)
				mc.queuedBytes += len(item.data)
			}
			mc.mu.Unlock()
		}
		mc.signal()
	}
}

func (mc *managedChannel) signal() {
	select {
	case mc.notifyCh <- struct{}{}:
	default:
	}
}
