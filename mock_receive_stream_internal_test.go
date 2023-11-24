// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/nofish24/quic-go (interfaces: ReceiveStreamI)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package quic -self_package github.com/nofish24/quic-go -destination mock_receive_stream_internal_test.go github.com/nofish24/quic-go ReceiveStreamI
//
// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"
	time "time"

	protocol "github.com/nofish24/quic-go/internal/protocol"
	qerr "github.com/nofish24/quic-go/internal/qerr"
	wire "github.com/nofish24/quic-go/internal/wire"
	gomock "go.uber.org/mock/gomock"
)

// MockReceiveStreamI is a mock of ReceiveStreamI interface.
type MockReceiveStreamI struct {
	ctrl     *gomock.Controller
	recorder *MockReceiveStreamIMockRecorder
}

// MockReceiveStreamIMockRecorder is the mock recorder for MockReceiveStreamI.
type MockReceiveStreamIMockRecorder struct {
	mock *MockReceiveStreamI
}

// NewMockReceiveStreamI creates a new mock instance.
func NewMockReceiveStreamI(ctrl *gomock.Controller) *MockReceiveStreamI {
	mock := &MockReceiveStreamI{ctrl: ctrl}
	mock.recorder = &MockReceiveStreamIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockReceiveStreamI) EXPECT() *MockReceiveStreamIMockRecorder {
	return m.recorder
}

// CancelRead mocks base method.
func (m *MockReceiveStreamI) CancelRead(arg0 qerr.StreamErrorCode) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "CancelRead", arg0)
}

// CancelRead indicates an expected call of CancelRead.
func (mr *MockReceiveStreamIMockRecorder) CancelRead(arg0 any) *ReceiveStreamICancelReadCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CancelRead", reflect.TypeOf((*MockReceiveStreamI)(nil).CancelRead), arg0)
	return &ReceiveStreamICancelReadCall{Call: call}
}

// ReceiveStreamICancelReadCall wrap *gomock.Call
type ReceiveStreamICancelReadCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ReceiveStreamICancelReadCall) Return() *ReceiveStreamICancelReadCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ReceiveStreamICancelReadCall) Do(f func(qerr.StreamErrorCode)) *ReceiveStreamICancelReadCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ReceiveStreamICancelReadCall) DoAndReturn(f func(qerr.StreamErrorCode)) *ReceiveStreamICancelReadCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Read mocks base method.
func (m *MockReceiveStreamI) Read(arg0 []byte) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Read", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Read indicates an expected call of Read.
func (mr *MockReceiveStreamIMockRecorder) Read(arg0 any) *ReceiveStreamIReadCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Read", reflect.TypeOf((*MockReceiveStreamI)(nil).Read), arg0)
	return &ReceiveStreamIReadCall{Call: call}
}

// ReceiveStreamIReadCall wrap *gomock.Call
type ReceiveStreamIReadCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ReceiveStreamIReadCall) Return(arg0 int, arg1 error) *ReceiveStreamIReadCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ReceiveStreamIReadCall) Do(f func([]byte) (int, error)) *ReceiveStreamIReadCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ReceiveStreamIReadCall) DoAndReturn(f func([]byte) (int, error)) *ReceiveStreamIReadCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SetReadDeadline mocks base method.
func (m *MockReceiveStreamI) SetReadDeadline(arg0 time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetReadDeadline", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetReadDeadline indicates an expected call of SetReadDeadline.
func (mr *MockReceiveStreamIMockRecorder) SetReadDeadline(arg0 any) *ReceiveStreamISetReadDeadlineCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetReadDeadline", reflect.TypeOf((*MockReceiveStreamI)(nil).SetReadDeadline), arg0)
	return &ReceiveStreamISetReadDeadlineCall{Call: call}
}

// ReceiveStreamISetReadDeadlineCall wrap *gomock.Call
type ReceiveStreamISetReadDeadlineCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ReceiveStreamISetReadDeadlineCall) Return(arg0 error) *ReceiveStreamISetReadDeadlineCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ReceiveStreamISetReadDeadlineCall) Do(f func(time.Time) error) *ReceiveStreamISetReadDeadlineCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ReceiveStreamISetReadDeadlineCall) DoAndReturn(f func(time.Time) error) *ReceiveStreamISetReadDeadlineCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// StreamID mocks base method.
func (m *MockReceiveStreamI) StreamID() protocol.StreamID {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StreamID")
	ret0, _ := ret[0].(protocol.StreamID)
	return ret0
}

// StreamID indicates an expected call of StreamID.
func (mr *MockReceiveStreamIMockRecorder) StreamID() *ReceiveStreamIStreamIDCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StreamID", reflect.TypeOf((*MockReceiveStreamI)(nil).StreamID))
	return &ReceiveStreamIStreamIDCall{Call: call}
}

// ReceiveStreamIStreamIDCall wrap *gomock.Call
type ReceiveStreamIStreamIDCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ReceiveStreamIStreamIDCall) Return(arg0 protocol.StreamID) *ReceiveStreamIStreamIDCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ReceiveStreamIStreamIDCall) Do(f func() protocol.StreamID) *ReceiveStreamIStreamIDCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ReceiveStreamIStreamIDCall) DoAndReturn(f func() protocol.StreamID) *ReceiveStreamIStreamIDCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// closeForShutdown mocks base method.
func (m *MockReceiveStreamI) closeForShutdown(arg0 error) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "closeForShutdown", arg0)
}

// closeForShutdown indicates an expected call of closeForShutdown.
func (mr *MockReceiveStreamIMockRecorder) closeForShutdown(arg0 any) *ReceiveStreamIcloseForShutdownCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "closeForShutdown", reflect.TypeOf((*MockReceiveStreamI)(nil).closeForShutdown), arg0)
	return &ReceiveStreamIcloseForShutdownCall{Call: call}
}

// ReceiveStreamIcloseForShutdownCall wrap *gomock.Call
type ReceiveStreamIcloseForShutdownCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ReceiveStreamIcloseForShutdownCall) Return() *ReceiveStreamIcloseForShutdownCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ReceiveStreamIcloseForShutdownCall) Do(f func(error)) *ReceiveStreamIcloseForShutdownCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ReceiveStreamIcloseForShutdownCall) DoAndReturn(f func(error)) *ReceiveStreamIcloseForShutdownCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// getWindowUpdate mocks base method.
func (m *MockReceiveStreamI) getWindowUpdate() protocol.ByteCount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "getWindowUpdate")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// getWindowUpdate indicates an expected call of getWindowUpdate.
func (mr *MockReceiveStreamIMockRecorder) getWindowUpdate() *ReceiveStreamIgetWindowUpdateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "getWindowUpdate", reflect.TypeOf((*MockReceiveStreamI)(nil).getWindowUpdate))
	return &ReceiveStreamIgetWindowUpdateCall{Call: call}
}

// ReceiveStreamIgetWindowUpdateCall wrap *gomock.Call
type ReceiveStreamIgetWindowUpdateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ReceiveStreamIgetWindowUpdateCall) Return(arg0 protocol.ByteCount) *ReceiveStreamIgetWindowUpdateCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ReceiveStreamIgetWindowUpdateCall) Do(f func() protocol.ByteCount) *ReceiveStreamIgetWindowUpdateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ReceiveStreamIgetWindowUpdateCall) DoAndReturn(f func() protocol.ByteCount) *ReceiveStreamIgetWindowUpdateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// handleResetStreamFrame mocks base method.
func (m *MockReceiveStreamI) handleResetStreamFrame(arg0 *wire.ResetStreamFrame) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "handleResetStreamFrame", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// handleResetStreamFrame indicates an expected call of handleResetStreamFrame.
func (mr *MockReceiveStreamIMockRecorder) handleResetStreamFrame(arg0 any) *ReceiveStreamIhandleResetStreamFrameCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "handleResetStreamFrame", reflect.TypeOf((*MockReceiveStreamI)(nil).handleResetStreamFrame), arg0)
	return &ReceiveStreamIhandleResetStreamFrameCall{Call: call}
}

// ReceiveStreamIhandleResetStreamFrameCall wrap *gomock.Call
type ReceiveStreamIhandleResetStreamFrameCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ReceiveStreamIhandleResetStreamFrameCall) Return(arg0 error) *ReceiveStreamIhandleResetStreamFrameCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ReceiveStreamIhandleResetStreamFrameCall) Do(f func(*wire.ResetStreamFrame) error) *ReceiveStreamIhandleResetStreamFrameCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ReceiveStreamIhandleResetStreamFrameCall) DoAndReturn(f func(*wire.ResetStreamFrame) error) *ReceiveStreamIhandleResetStreamFrameCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// handleStreamFrame mocks base method.
func (m *MockReceiveStreamI) handleStreamFrame(arg0 *wire.StreamFrame) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "handleStreamFrame", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// handleStreamFrame indicates an expected call of handleStreamFrame.
func (mr *MockReceiveStreamIMockRecorder) handleStreamFrame(arg0 any) *ReceiveStreamIhandleStreamFrameCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "handleStreamFrame", reflect.TypeOf((*MockReceiveStreamI)(nil).handleStreamFrame), arg0)
	return &ReceiveStreamIhandleStreamFrameCall{Call: call}
}

// ReceiveStreamIhandleStreamFrameCall wrap *gomock.Call
type ReceiveStreamIhandleStreamFrameCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ReceiveStreamIhandleStreamFrameCall) Return(arg0 error) *ReceiveStreamIhandleStreamFrameCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ReceiveStreamIhandleStreamFrameCall) Do(f func(*wire.StreamFrame) error) *ReceiveStreamIhandleStreamFrameCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ReceiveStreamIhandleStreamFrameCall) DoAndReturn(f func(*wire.StreamFrame) error) *ReceiveStreamIhandleStreamFrameCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
