// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/nofish24/quic-go/internal/mocks/logging (interfaces: Tracer)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package internal -destination internal/tracer.go github.com/nofish24/quic-go/internal/mocks/logging Tracer
//
// Package internal is a generated GoMock package.
package internal

import (
	net "net"
	reflect "reflect"

	protocol "github.com/nofish24/quic-go/internal/protocol"
	wire "github.com/nofish24/quic-go/internal/wire"
	logging "github.com/nofish24/quic-go/logging"
	gomock "go.uber.org/mock/gomock"
)

// MockTracer is a mock of Tracer interface.
type MockTracer struct {
	ctrl     *gomock.Controller
	recorder *MockTracerMockRecorder
}

// MockTracerMockRecorder is the mock recorder for MockTracer.
type MockTracerMockRecorder struct {
	mock *MockTracer
}

// NewMockTracer creates a new mock instance.
func NewMockTracer(ctrl *gomock.Controller) *MockTracer {
	mock := &MockTracer{ctrl: ctrl}
	mock.recorder = &MockTracerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTracer) EXPECT() *MockTracerMockRecorder {
	return m.recorder
}

// DroppedPacket mocks base method.
func (m *MockTracer) DroppedPacket(arg0 net.Addr, arg1 logging.PacketType, arg2 protocol.ByteCount, arg3 logging.PacketDropReason) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DroppedPacket", arg0, arg1, arg2, arg3)
}

// DroppedPacket indicates an expected call of DroppedPacket.
func (mr *MockTracerMockRecorder) DroppedPacket(arg0, arg1, arg2, arg3 any) *TracerDroppedPacketCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DroppedPacket", reflect.TypeOf((*MockTracer)(nil).DroppedPacket), arg0, arg1, arg2, arg3)
	return &TracerDroppedPacketCall{Call: call}
}

// TracerDroppedPacketCall wrap *gomock.Call
type TracerDroppedPacketCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TracerDroppedPacketCall) Return() *TracerDroppedPacketCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TracerDroppedPacketCall) Do(f func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason)) *TracerDroppedPacketCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TracerDroppedPacketCall) DoAndReturn(f func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason)) *TracerDroppedPacketCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SentPacket mocks base method.
func (m *MockTracer) SentPacket(arg0 net.Addr, arg1 *wire.Header, arg2 protocol.ByteCount, arg3 []logging.Frame) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SentPacket", arg0, arg1, arg2, arg3)
}

// SentPacket indicates an expected call of SentPacket.
func (mr *MockTracerMockRecorder) SentPacket(arg0, arg1, arg2, arg3 any) *TracerSentPacketCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SentPacket", reflect.TypeOf((*MockTracer)(nil).SentPacket), arg0, arg1, arg2, arg3)
	return &TracerSentPacketCall{Call: call}
}

// TracerSentPacketCall wrap *gomock.Call
type TracerSentPacketCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TracerSentPacketCall) Return() *TracerSentPacketCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TracerSentPacketCall) Do(f func(net.Addr, *wire.Header, protocol.ByteCount, []logging.Frame)) *TracerSentPacketCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TracerSentPacketCall) DoAndReturn(f func(net.Addr, *wire.Header, protocol.ByteCount, []logging.Frame)) *TracerSentPacketCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SentVersionNegotiationPacket mocks base method.
func (m *MockTracer) SentVersionNegotiationPacket(arg0 net.Addr, arg1, arg2 protocol.ArbitraryLenConnectionID, arg3 []protocol.VersionNumber) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SentVersionNegotiationPacket", arg0, arg1, arg2, arg3)
}

// SentVersionNegotiationPacket indicates an expected call of SentVersionNegotiationPacket.
func (mr *MockTracerMockRecorder) SentVersionNegotiationPacket(arg0, arg1, arg2, arg3 any) *TracerSentVersionNegotiationPacketCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SentVersionNegotiationPacket", reflect.TypeOf((*MockTracer)(nil).SentVersionNegotiationPacket), arg0, arg1, arg2, arg3)
	return &TracerSentVersionNegotiationPacketCall{Call: call}
}

// TracerSentVersionNegotiationPacketCall wrap *gomock.Call
type TracerSentVersionNegotiationPacketCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TracerSentVersionNegotiationPacketCall) Return() *TracerSentVersionNegotiationPacketCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TracerSentVersionNegotiationPacketCall) Do(f func(net.Addr, protocol.ArbitraryLenConnectionID, protocol.ArbitraryLenConnectionID, []protocol.VersionNumber)) *TracerSentVersionNegotiationPacketCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TracerSentVersionNegotiationPacketCall) DoAndReturn(f func(net.Addr, protocol.ArbitraryLenConnectionID, protocol.ArbitraryLenConnectionID, []protocol.VersionNumber)) *TracerSentVersionNegotiationPacketCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
