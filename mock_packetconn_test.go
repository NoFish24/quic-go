// Code generated by MockGen. DO NOT EDIT.
// Source: net (interfaces: PacketConn)
//
// Generated by this command:
//
//	mockgen -typed -package quic -self_package github.com/nofish24/quic-go -self_package github.com/nofish24/quic-go -destination mock_packetconn_test.go net PacketConn
//
// Package quic is a generated GoMock package.
package quic

import (
	net "net"
	reflect "reflect"
	time "time"

	gomock "go.uber.org/mock/gomock"
)

// MockPacketConn is a mock of PacketConn interface.
type MockPacketConn struct {
	ctrl     *gomock.Controller
	recorder *MockPacketConnMockRecorder
}

// MockPacketConnMockRecorder is the mock recorder for MockPacketConn.
type MockPacketConnMockRecorder struct {
	mock *MockPacketConn
}

// NewMockPacketConn creates a new mock instance.
func NewMockPacketConn(ctrl *gomock.Controller) *MockPacketConn {
	mock := &MockPacketConn{ctrl: ctrl}
	mock.recorder = &MockPacketConnMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPacketConn) EXPECT() *MockPacketConnMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockPacketConn) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockPacketConnMockRecorder) Close() *PacketConnCloseCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockPacketConn)(nil).Close))
	return &PacketConnCloseCall{Call: call}
}

// PacketConnCloseCall wrap *gomock.Call
type PacketConnCloseCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *PacketConnCloseCall) Return(arg0 error) *PacketConnCloseCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *PacketConnCloseCall) Do(f func() error) *PacketConnCloseCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *PacketConnCloseCall) DoAndReturn(f func() error) *PacketConnCloseCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// LocalAddr mocks base method.
func (m *MockPacketConn) LocalAddr() net.Addr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LocalAddr")
	ret0, _ := ret[0].(net.Addr)
	return ret0
}

// LocalAddr indicates an expected call of LocalAddr.
func (mr *MockPacketConnMockRecorder) LocalAddr() *PacketConnLocalAddrCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LocalAddr", reflect.TypeOf((*MockPacketConn)(nil).LocalAddr))
	return &PacketConnLocalAddrCall{Call: call}
}

// PacketConnLocalAddrCall wrap *gomock.Call
type PacketConnLocalAddrCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *PacketConnLocalAddrCall) Return(arg0 net.Addr) *PacketConnLocalAddrCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *PacketConnLocalAddrCall) Do(f func() net.Addr) *PacketConnLocalAddrCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *PacketConnLocalAddrCall) DoAndReturn(f func() net.Addr) *PacketConnLocalAddrCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReadFrom mocks base method.
func (m *MockPacketConn) ReadFrom(arg0 []byte) (int, net.Addr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadFrom", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(net.Addr)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ReadFrom indicates an expected call of ReadFrom.
func (mr *MockPacketConnMockRecorder) ReadFrom(arg0 any) *PacketConnReadFromCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadFrom", reflect.TypeOf((*MockPacketConn)(nil).ReadFrom), arg0)
	return &PacketConnReadFromCall{Call: call}
}

// PacketConnReadFromCall wrap *gomock.Call
type PacketConnReadFromCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *PacketConnReadFromCall) Return(arg0 int, arg1 net.Addr, arg2 error) *PacketConnReadFromCall {
	c.Call = c.Call.Return(arg0, arg1, arg2)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *PacketConnReadFromCall) Do(f func([]byte) (int, net.Addr, error)) *PacketConnReadFromCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *PacketConnReadFromCall) DoAndReturn(f func([]byte) (int, net.Addr, error)) *PacketConnReadFromCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SetDeadline mocks base method.
func (m *MockPacketConn) SetDeadline(arg0 time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetDeadline", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetDeadline indicates an expected call of SetDeadline.
func (mr *MockPacketConnMockRecorder) SetDeadline(arg0 any) *PacketConnSetDeadlineCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetDeadline", reflect.TypeOf((*MockPacketConn)(nil).SetDeadline), arg0)
	return &PacketConnSetDeadlineCall{Call: call}
}

// PacketConnSetDeadlineCall wrap *gomock.Call
type PacketConnSetDeadlineCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *PacketConnSetDeadlineCall) Return(arg0 error) *PacketConnSetDeadlineCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *PacketConnSetDeadlineCall) Do(f func(time.Time) error) *PacketConnSetDeadlineCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *PacketConnSetDeadlineCall) DoAndReturn(f func(time.Time) error) *PacketConnSetDeadlineCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SetReadDeadline mocks base method.
func (m *MockPacketConn) SetReadDeadline(arg0 time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetReadDeadline", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetReadDeadline indicates an expected call of SetReadDeadline.
func (mr *MockPacketConnMockRecorder) SetReadDeadline(arg0 any) *PacketConnSetReadDeadlineCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetReadDeadline", reflect.TypeOf((*MockPacketConn)(nil).SetReadDeadline), arg0)
	return &PacketConnSetReadDeadlineCall{Call: call}
}

// PacketConnSetReadDeadlineCall wrap *gomock.Call
type PacketConnSetReadDeadlineCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *PacketConnSetReadDeadlineCall) Return(arg0 error) *PacketConnSetReadDeadlineCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *PacketConnSetReadDeadlineCall) Do(f func(time.Time) error) *PacketConnSetReadDeadlineCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *PacketConnSetReadDeadlineCall) DoAndReturn(f func(time.Time) error) *PacketConnSetReadDeadlineCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SetWriteDeadline mocks base method.
func (m *MockPacketConn) SetWriteDeadline(arg0 time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetWriteDeadline", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetWriteDeadline indicates an expected call of SetWriteDeadline.
func (mr *MockPacketConnMockRecorder) SetWriteDeadline(arg0 any) *PacketConnSetWriteDeadlineCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetWriteDeadline", reflect.TypeOf((*MockPacketConn)(nil).SetWriteDeadline), arg0)
	return &PacketConnSetWriteDeadlineCall{Call: call}
}

// PacketConnSetWriteDeadlineCall wrap *gomock.Call
type PacketConnSetWriteDeadlineCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *PacketConnSetWriteDeadlineCall) Return(arg0 error) *PacketConnSetWriteDeadlineCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *PacketConnSetWriteDeadlineCall) Do(f func(time.Time) error) *PacketConnSetWriteDeadlineCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *PacketConnSetWriteDeadlineCall) DoAndReturn(f func(time.Time) error) *PacketConnSetWriteDeadlineCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// WriteTo mocks base method.
func (m *MockPacketConn) WriteTo(arg0 []byte, arg1 net.Addr) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteTo", arg0, arg1)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WriteTo indicates an expected call of WriteTo.
func (mr *MockPacketConnMockRecorder) WriteTo(arg0, arg1 any) *PacketConnWriteToCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteTo", reflect.TypeOf((*MockPacketConn)(nil).WriteTo), arg0, arg1)
	return &PacketConnWriteToCall{Call: call}
}

// PacketConnWriteToCall wrap *gomock.Call
type PacketConnWriteToCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *PacketConnWriteToCall) Return(arg0 int, arg1 error) *PacketConnWriteToCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *PacketConnWriteToCall) Do(f func([]byte, net.Addr) (int, error)) *PacketConnWriteToCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *PacketConnWriteToCall) DoAndReturn(f func([]byte, net.Addr) (int, error)) *PacketConnWriteToCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
