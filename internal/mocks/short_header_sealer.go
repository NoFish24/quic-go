// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/nofish24/quic-go/internal/handshake (interfaces: ShortHeaderSealer)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package mocks -destination short_header_sealer.go github.com/nofish24/quic-go/internal/handshake ShortHeaderSealer
//
// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	protocol "github.com/nofish24/quic-go/internal/protocol"
	gomock "go.uber.org/mock/gomock"
)

// MockShortHeaderSealer is a mock of ShortHeaderSealer interface.
type MockShortHeaderSealer struct {
	ctrl     *gomock.Controller
	recorder *MockShortHeaderSealerMockRecorder
}

// MockShortHeaderSealerMockRecorder is the mock recorder for MockShortHeaderSealer.
type MockShortHeaderSealerMockRecorder struct {
	mock *MockShortHeaderSealer
}

// NewMockShortHeaderSealer creates a new mock instance.
func NewMockShortHeaderSealer(ctrl *gomock.Controller) *MockShortHeaderSealer {
	mock := &MockShortHeaderSealer{ctrl: ctrl}
	mock.recorder = &MockShortHeaderSealerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockShortHeaderSealer) EXPECT() *MockShortHeaderSealerMockRecorder {
	return m.recorder
}

// EncryptHeader mocks base method.
func (m *MockShortHeaderSealer) EncryptHeader(arg0 []byte, arg1 *byte, arg2 []byte) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "EncryptHeader", arg0, arg1, arg2)
}

// EncryptHeader indicates an expected call of EncryptHeader.
func (mr *MockShortHeaderSealerMockRecorder) EncryptHeader(arg0, arg1, arg2 any) *ShortHeaderSealerEncryptHeaderCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptHeader", reflect.TypeOf((*MockShortHeaderSealer)(nil).EncryptHeader), arg0, arg1, arg2)
	return &ShortHeaderSealerEncryptHeaderCall{Call: call}
}

// ShortHeaderSealerEncryptHeaderCall wrap *gomock.Call
type ShortHeaderSealerEncryptHeaderCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ShortHeaderSealerEncryptHeaderCall) Return() *ShortHeaderSealerEncryptHeaderCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ShortHeaderSealerEncryptHeaderCall) Do(f func([]byte, *byte, []byte)) *ShortHeaderSealerEncryptHeaderCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ShortHeaderSealerEncryptHeaderCall) DoAndReturn(f func([]byte, *byte, []byte)) *ShortHeaderSealerEncryptHeaderCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// KeyPhase mocks base method.
func (m *MockShortHeaderSealer) KeyPhase() protocol.KeyPhaseBit {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "KeyPhase")
	ret0, _ := ret[0].(protocol.KeyPhaseBit)
	return ret0
}

// KeyPhase indicates an expected call of KeyPhase.
func (mr *MockShortHeaderSealerMockRecorder) KeyPhase() *ShortHeaderSealerKeyPhaseCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KeyPhase", reflect.TypeOf((*MockShortHeaderSealer)(nil).KeyPhase))
	return &ShortHeaderSealerKeyPhaseCall{Call: call}
}

// ShortHeaderSealerKeyPhaseCall wrap *gomock.Call
type ShortHeaderSealerKeyPhaseCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ShortHeaderSealerKeyPhaseCall) Return(arg0 protocol.KeyPhaseBit) *ShortHeaderSealerKeyPhaseCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ShortHeaderSealerKeyPhaseCall) Do(f func() protocol.KeyPhaseBit) *ShortHeaderSealerKeyPhaseCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ShortHeaderSealerKeyPhaseCall) DoAndReturn(f func() protocol.KeyPhaseBit) *ShortHeaderSealerKeyPhaseCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Overhead mocks base method.
func (m *MockShortHeaderSealer) Overhead() int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Overhead")
	ret0, _ := ret[0].(int)
	return ret0
}

// Overhead indicates an expected call of Overhead.
func (mr *MockShortHeaderSealerMockRecorder) Overhead() *ShortHeaderSealerOverheadCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Overhead", reflect.TypeOf((*MockShortHeaderSealer)(nil).Overhead))
	return &ShortHeaderSealerOverheadCall{Call: call}
}

// ShortHeaderSealerOverheadCall wrap *gomock.Call
type ShortHeaderSealerOverheadCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ShortHeaderSealerOverheadCall) Return(arg0 int) *ShortHeaderSealerOverheadCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ShortHeaderSealerOverheadCall) Do(f func() int) *ShortHeaderSealerOverheadCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ShortHeaderSealerOverheadCall) DoAndReturn(f func() int) *ShortHeaderSealerOverheadCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Seal mocks base method.
func (m *MockShortHeaderSealer) Seal(arg0, arg1 []byte, arg2 protocol.PacketNumber, arg3 []byte) []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Seal", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].([]byte)
	return ret0
}

// Seal indicates an expected call of Seal.
func (mr *MockShortHeaderSealerMockRecorder) Seal(arg0, arg1, arg2, arg3 any) *ShortHeaderSealerSealCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Seal", reflect.TypeOf((*MockShortHeaderSealer)(nil).Seal), arg0, arg1, arg2, arg3)
	return &ShortHeaderSealerSealCall{Call: call}
}

// ShortHeaderSealerSealCall wrap *gomock.Call
type ShortHeaderSealerSealCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ShortHeaderSealerSealCall) Return(arg0 []byte) *ShortHeaderSealerSealCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ShortHeaderSealerSealCall) Do(f func([]byte, []byte, protocol.PacketNumber, []byte) []byte) *ShortHeaderSealerSealCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ShortHeaderSealerSealCall) DoAndReturn(f func([]byte, []byte, protocol.PacketNumber, []byte) []byte) *ShortHeaderSealerSealCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
