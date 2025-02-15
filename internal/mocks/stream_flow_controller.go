// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/nofish24/quic-go/internal/flowcontrol (interfaces: StreamFlowController)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package mocks -destination stream_flow_controller.go github.com/nofish24/quic-go/internal/flowcontrol StreamFlowController
//
// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	protocol "github.com/nofish24/quic-go/internal/protocol"
	gomock "go.uber.org/mock/gomock"
)

// MockStreamFlowController is a mock of StreamFlowController interface.
type MockStreamFlowController struct {
	ctrl     *gomock.Controller
	recorder *MockStreamFlowControllerMockRecorder
}

// MockStreamFlowControllerMockRecorder is the mock recorder for MockStreamFlowController.
type MockStreamFlowControllerMockRecorder struct {
	mock *MockStreamFlowController
}

// NewMockStreamFlowController creates a new mock instance.
func NewMockStreamFlowController(ctrl *gomock.Controller) *MockStreamFlowController {
	mock := &MockStreamFlowController{ctrl: ctrl}
	mock.recorder = &MockStreamFlowControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStreamFlowController) EXPECT() *MockStreamFlowControllerMockRecorder {
	return m.recorder
}

// Abandon mocks base method.
func (m *MockStreamFlowController) Abandon() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Abandon")
}

// Abandon indicates an expected call of Abandon.
func (mr *MockStreamFlowControllerMockRecorder) Abandon() *StreamFlowControllerAbandonCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Abandon", reflect.TypeOf((*MockStreamFlowController)(nil).Abandon))
	return &StreamFlowControllerAbandonCall{Call: call}
}

// StreamFlowControllerAbandonCall wrap *gomock.Call
type StreamFlowControllerAbandonCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamFlowControllerAbandonCall) Return() *StreamFlowControllerAbandonCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamFlowControllerAbandonCall) Do(f func()) *StreamFlowControllerAbandonCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamFlowControllerAbandonCall) DoAndReturn(f func()) *StreamFlowControllerAbandonCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AddBytesRead mocks base method.
func (m *MockStreamFlowController) AddBytesRead(arg0 protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddBytesRead", arg0)
}

// AddBytesRead indicates an expected call of AddBytesRead.
func (mr *MockStreamFlowControllerMockRecorder) AddBytesRead(arg0 any) *StreamFlowControllerAddBytesReadCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddBytesRead", reflect.TypeOf((*MockStreamFlowController)(nil).AddBytesRead), arg0)
	return &StreamFlowControllerAddBytesReadCall{Call: call}
}

// StreamFlowControllerAddBytesReadCall wrap *gomock.Call
type StreamFlowControllerAddBytesReadCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamFlowControllerAddBytesReadCall) Return() *StreamFlowControllerAddBytesReadCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamFlowControllerAddBytesReadCall) Do(f func(protocol.ByteCount)) *StreamFlowControllerAddBytesReadCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamFlowControllerAddBytesReadCall) DoAndReturn(f func(protocol.ByteCount)) *StreamFlowControllerAddBytesReadCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AddBytesSent mocks base method.
func (m *MockStreamFlowController) AddBytesSent(arg0 protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddBytesSent", arg0)
}

// AddBytesSent indicates an expected call of AddBytesSent.
func (mr *MockStreamFlowControllerMockRecorder) AddBytesSent(arg0 any) *StreamFlowControllerAddBytesSentCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddBytesSent", reflect.TypeOf((*MockStreamFlowController)(nil).AddBytesSent), arg0)
	return &StreamFlowControllerAddBytesSentCall{Call: call}
}

// StreamFlowControllerAddBytesSentCall wrap *gomock.Call
type StreamFlowControllerAddBytesSentCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamFlowControllerAddBytesSentCall) Return() *StreamFlowControllerAddBytesSentCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamFlowControllerAddBytesSentCall) Do(f func(protocol.ByteCount)) *StreamFlowControllerAddBytesSentCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamFlowControllerAddBytesSentCall) DoAndReturn(f func(protocol.ByteCount)) *StreamFlowControllerAddBytesSentCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetWindowUpdate mocks base method.
func (m *MockStreamFlowController) GetWindowUpdate() protocol.ByteCount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetWindowUpdate")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// GetWindowUpdate indicates an expected call of GetWindowUpdate.
func (mr *MockStreamFlowControllerMockRecorder) GetWindowUpdate() *StreamFlowControllerGetWindowUpdateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetWindowUpdate", reflect.TypeOf((*MockStreamFlowController)(nil).GetWindowUpdate))
	return &StreamFlowControllerGetWindowUpdateCall{Call: call}
}

// StreamFlowControllerGetWindowUpdateCall wrap *gomock.Call
type StreamFlowControllerGetWindowUpdateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamFlowControllerGetWindowUpdateCall) Return(arg0 protocol.ByteCount) *StreamFlowControllerGetWindowUpdateCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamFlowControllerGetWindowUpdateCall) Do(f func() protocol.ByteCount) *StreamFlowControllerGetWindowUpdateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamFlowControllerGetWindowUpdateCall) DoAndReturn(f func() protocol.ByteCount) *StreamFlowControllerGetWindowUpdateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// IsNewlyBlocked mocks base method.
func (m *MockStreamFlowController) IsNewlyBlocked() (bool, protocol.ByteCount) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsNewlyBlocked")
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(protocol.ByteCount)
	return ret0, ret1
}

// IsNewlyBlocked indicates an expected call of IsNewlyBlocked.
func (mr *MockStreamFlowControllerMockRecorder) IsNewlyBlocked() *StreamFlowControllerIsNewlyBlockedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsNewlyBlocked", reflect.TypeOf((*MockStreamFlowController)(nil).IsNewlyBlocked))
	return &StreamFlowControllerIsNewlyBlockedCall{Call: call}
}

// StreamFlowControllerIsNewlyBlockedCall wrap *gomock.Call
type StreamFlowControllerIsNewlyBlockedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamFlowControllerIsNewlyBlockedCall) Return(arg0 bool, arg1 protocol.ByteCount) *StreamFlowControllerIsNewlyBlockedCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamFlowControllerIsNewlyBlockedCall) Do(f func() (bool, protocol.ByteCount)) *StreamFlowControllerIsNewlyBlockedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamFlowControllerIsNewlyBlockedCall) DoAndReturn(f func() (bool, protocol.ByteCount)) *StreamFlowControllerIsNewlyBlockedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SendWindowSize mocks base method.
func (m *MockStreamFlowController) SendWindowSize() protocol.ByteCount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendWindowSize")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// SendWindowSize indicates an expected call of SendWindowSize.
func (mr *MockStreamFlowControllerMockRecorder) SendWindowSize() *StreamFlowControllerSendWindowSizeCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendWindowSize", reflect.TypeOf((*MockStreamFlowController)(nil).SendWindowSize))
	return &StreamFlowControllerSendWindowSizeCall{Call: call}
}

// StreamFlowControllerSendWindowSizeCall wrap *gomock.Call
type StreamFlowControllerSendWindowSizeCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamFlowControllerSendWindowSizeCall) Return(arg0 protocol.ByteCount) *StreamFlowControllerSendWindowSizeCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamFlowControllerSendWindowSizeCall) Do(f func() protocol.ByteCount) *StreamFlowControllerSendWindowSizeCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamFlowControllerSendWindowSizeCall) DoAndReturn(f func() protocol.ByteCount) *StreamFlowControllerSendWindowSizeCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// UpdateHighestReceived mocks base method.
func (m *MockStreamFlowController) UpdateHighestReceived(arg0 protocol.ByteCount, arg1 bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateHighestReceived", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateHighestReceived indicates an expected call of UpdateHighestReceived.
func (mr *MockStreamFlowControllerMockRecorder) UpdateHighestReceived(arg0, arg1 any) *StreamFlowControllerUpdateHighestReceivedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateHighestReceived", reflect.TypeOf((*MockStreamFlowController)(nil).UpdateHighestReceived), arg0, arg1)
	return &StreamFlowControllerUpdateHighestReceivedCall{Call: call}
}

// StreamFlowControllerUpdateHighestReceivedCall wrap *gomock.Call
type StreamFlowControllerUpdateHighestReceivedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamFlowControllerUpdateHighestReceivedCall) Return(arg0 error) *StreamFlowControllerUpdateHighestReceivedCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamFlowControllerUpdateHighestReceivedCall) Do(f func(protocol.ByteCount, bool) error) *StreamFlowControllerUpdateHighestReceivedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamFlowControllerUpdateHighestReceivedCall) DoAndReturn(f func(protocol.ByteCount, bool) error) *StreamFlowControllerUpdateHighestReceivedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// UpdateSendWindow mocks base method.
func (m *MockStreamFlowController) UpdateSendWindow(arg0 protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UpdateSendWindow", arg0)
}

// UpdateSendWindow indicates an expected call of UpdateSendWindow.
func (mr *MockStreamFlowControllerMockRecorder) UpdateSendWindow(arg0 any) *StreamFlowControllerUpdateSendWindowCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSendWindow", reflect.TypeOf((*MockStreamFlowController)(nil).UpdateSendWindow), arg0)
	return &StreamFlowControllerUpdateSendWindowCall{Call: call}
}

// StreamFlowControllerUpdateSendWindowCall wrap *gomock.Call
type StreamFlowControllerUpdateSendWindowCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamFlowControllerUpdateSendWindowCall) Return() *StreamFlowControllerUpdateSendWindowCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamFlowControllerUpdateSendWindowCall) Do(f func(protocol.ByteCount)) *StreamFlowControllerUpdateSendWindowCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamFlowControllerUpdateSendWindowCall) DoAndReturn(f func(protocol.ByteCount)) *StreamFlowControllerUpdateSendWindowCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
