// Code generated by goctl. DO NOT EDIT.
package types

type LoginReply struct {
	Token string `json:"token"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}