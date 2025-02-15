// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/nofish24/quic-go/internal/flowcontrol (interfaces: ConnectionFlowController)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package mocks -destination connection_flow_controller.go github.com/nofish24/quic-go/internal/flowcontrol ConnectionFlowController
//
// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	protocol "github.com/nofish24/quic-go/internal/protocol"
	gomock "go.uber.org/mock/gomock"
)

// MockConnectionFlowController is a mock of ConnectionFlowController interface.
type MockConnectionFlowController struct {
	ctrl     *gomock.Controller
	recorder *MockConnectionFlowControllerMockRecorder
}

// MockConnectionFlowControllerMockRecorder is the mock recorder for MockConnectionFlowController.
type MockConnectionFlowControllerMockRecorder struct {
	mock *MockConnectionFlowController
}

// NewMockConnectionFlowController creates a new mock instance.
func NewMockConnectionFlowController(ctrl *gomock.Controller) *MockConnectionFlowController {
	mock := &MockConnectionFlowController{ctrl: ctrl}
	mock.recorder = &MockConnectionFlowControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConnectionFlowController) EXPECT() *MockConnectionFlowControllerMockRecorder {
	return m.recorder
}

// AddBytesRead mocks base method.
func (m *MockConnectionFlowController) AddBytesRead(arg0 protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddBytesRead", arg0)
}

// AddBytesRead indicates an expected call of AddBytesRead.
func (mr *MockConnectionFlowControllerMockRecorder) AddBytesRead(arg0 any) *ConnectionFlowControllerAddBytesReadCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddBytesRead", reflect.TypeOf((*MockConnectionFlowController)(nil).AddBytesRead), arg0)
	return &ConnectionFlowControllerAddBytesReadCall{Call: call}
}

// ConnectionFlowControllerAddBytesReadCall wrap *gomock.Call
type ConnectionFlowControllerAddBytesReadCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ConnectionFlowControllerAddBytesReadCall) Return() *ConnectionFlowControllerAddBytesReadCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ConnectionFlowControllerAddBytesReadCall) Do(f func(protocol.ByteCount)) *ConnectionFlowControllerAddBytesReadCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ConnectionFlowControllerAddBytesReadCall) DoAndReturn(f func(protocol.ByteCount)) *ConnectionFlowControllerAddBytesReadCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AddBytesSent mocks base method.
func (m *MockConnectionFlowController) AddBytesSent(arg0 protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddBytesSent", arg0)
}

// AddBytesSent indicates an expected call of AddBytesSent.
func (mr *MockConnectionFlowControllerMockRecorder) AddBytesSent(arg0 any) *ConnectionFlowControllerAddBytesSentCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddBytesSent", reflect.TypeOf((*MockConnectionFlowController)(nil).AddBytesSent), arg0)
	return &ConnectionFlowControllerAddBytesSentCall{Call: call}
}

// ConnectionFlowControllerAddBytesSentCall wrap *gomock.Call
type ConnectionFlowControllerAddBytesSentCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ConnectionFlowControllerAddBytesSentCall) Return() *ConnectionFlowControllerAddBytesSentCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ConnectionFlowControllerAddBytesSentCall) Do(f func(protocol.ByteCount)) *ConnectionFlowControllerAddBytesSentCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ConnectionFlowControllerAddBytesSentCall) DoAndReturn(f func(protocol.ByteCount)) *ConnectionFlowControllerAddBytesSentCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetWindowUpdate mocks base method.
func (m *MockConnectionFlowController) GetWindowUpdate() protocol.ByteCount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetWindowUpdate")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// GetWindowUpdate indicates an expected call of GetWindowUpdate.
func (mr *MockConnectionFlowControllerMockRecorder) GetWindowUpdate() *ConnectionFlowControllerGetWindowUpdateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetWindowUpdate", reflect.TypeOf((*MockConnectionFlowController)(nil).GetWindowUpdate))
	return &ConnectionFlowControllerGetWindowUpdateCall{Call: call}
}

// ConnectionFlowControllerGetWindowUpdateCall wrap *gomock.Call
type ConnectionFlowControllerGetWindowUpdateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ConnectionFlowControllerGetWindowUpdateCall) Return(arg0 protocol.ByteCount) *ConnectionFlowControllerGetWindowUpdateCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ConnectionFlowControllerGetWindowUpdateCall) Do(f func() protocol.ByteCount) *ConnectionFlowControllerGetWindowUpdateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ConnectionFlowControllerGetWindowUpdateCall) DoAndReturn(f func() protocol.ByteCount) *ConnectionFlowControllerGetWindowUpdateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// IsNewlyBlocked mocks base method.
func (m *MockConnectionFlowController) IsNewlyBlocked() (bool, protocol.ByteCount) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsNewlyBlocked")
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(protocol.ByteCount)
	return ret0, ret1
}

// IsNewlyBlocked indicates an expected call of IsNewlyBlocked.
func (mr *MockConnectionFlowControllerMockRecorder) IsNewlyBlocked() *ConnectionFlowControllerIsNewlyBlockedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsNewlyBlocked", reflect.TypeOf((*MockConnectionFlowController)(nil).IsNewlyBlocked))
	return &ConnectionFlowControllerIsNewlyBlockedCall{Call: call}
}

// ConnectionFlowControllerIsNewlyBlockedCall wrap *gomock.Call
type ConnectionFlowControllerIsNewlyBlockedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ConnectionFlowControllerIsNewlyBlockedCall) Return(arg0 bool, arg1 protocol.ByteCount) *ConnectionFlowControllerIsNewlyBlockedCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ConnectionFlowControllerIsNewlyBlockedCall) Do(f func() (bool, protocol.ByteCount)) *ConnectionFlowControllerIsNewlyBlockedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ConnectionFlowControllerIsNewlyBlockedCall) DoAndReturn(f func() (bool, protocol.ByteCount)) *ConnectionFlowControllerIsNewlyBlockedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Reset mocks base method.
func (m *MockConnectionFlowController) Reset() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Reset")
	ret0, _ := ret[0].(error)
	return ret0
}

// Reset indicates an expected call of Reset.
func (mr *MockConnectionFlowControllerMockRecorder) Reset() *ConnectionFlowControllerResetCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reset", reflect.TypeOf((*MockConnectionFlowController)(nil).Reset))
	return &ConnectionFlowControllerResetCall{Call: call}
}

// ConnectionFlowControllerResetCall wrap *gomock.Call
type ConnectionFlowControllerResetCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ConnectionFlowControllerResetCall) Return(arg0 error) *ConnectionFlowControllerResetCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ConnectionFlowControllerResetCall) Do(f func() error) *ConnectionFlowControllerResetCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ConnectionFlowControllerResetCall) DoAndReturn(f func() error) *ConnectionFlowControllerResetCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SendWindowSize mocks base method.
func (m *MockConnectionFlowController) SendWindowSize() protocol.ByteCount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendWindowSize")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// SendWindowSize indicates an expected call of SendWindowSize.
func (mr *MockConnectionFlowControllerMockRecorder) SendWindowSize() *ConnectionFlowControllerSendWindowSizeCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendWindowSize", reflect.TypeOf((*MockConnectionFlowController)(nil).SendWindowSize))
	return &ConnectionFlowControllerSendWindowSizeCall{Call: call}
}

// ConnectionFlowControllerSendWindowSizeCall wrap *gomock.Call
type ConnectionFlowControllerSendWindowSizeCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ConnectionFlowControllerSendWindowSizeCall) Return(arg0 protocol.ByteCount) *ConnectionFlowControllerSendWindowSizeCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ConnectionFlowControllerSendWindowSizeCall) Do(f func() protocol.ByteCount) *ConnectionFlowControllerSendWindowSizeCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ConnectionFlowControllerSendWindowSizeCall) DoAndReturn(f func() protocol.ByteCount) *ConnectionFlowControllerSendWindowSizeCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// UpdateSendWindow mocks base method.
func (m *MockConnectionFlowController) UpdateSendWindow(arg0 protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UpdateSendWindow", arg0)
}

// UpdateSendWindow indicates an expected call of UpdateSendWindow.
func (mr *MockConnectionFlowControllerMockRecorder) UpdateSendWindow(arg0 any) *ConnectionFlowControllerUpdateSendWindowCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSendWindow", reflect.TypeOf((*MockConnectionFlowController)(nil).UpdateSendWindow), arg0)
	return &ConnectionFlowControllerUpdateSendWindowCall{Call: call}
}

// ConnectionFlowControllerUpdateSendWindowCall wrap *gomock.Call
type ConnectionFlowControllerUpdateSendWindowCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ConnectionFlowControllerUpdateSendWindowCall) Return() *ConnectionFlowControllerUpdateSendWindowCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ConnectionFlowControllerUpdateSendWindowCall) Do(f func(protocol.ByteCount)) *ConnectionFlowControllerUpdateSendWindowCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ConnectionFlowControllerUpdateSendWindowCall) DoAndReturn(f func(protocol.ByteCount)) *ConnectionFlowControllerUpdateSendWindowCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
