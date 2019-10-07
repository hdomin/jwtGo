package models

type User struct {
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
	Rol      string `json:"role"`
}
