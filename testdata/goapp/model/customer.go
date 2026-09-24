package model

// Customer is persisted with GORM.
type Customer struct {
	ID       int64  `json:"id" gorm:"primaryKey"`
	Contact  string `json:"contact" gorm:"column:so_dien_thoai"`
	Email    string `json:"email"`
	CCCD     string `json:"cccd"`
	Nickname string `json:"nickname"`
	Note     string `json:"note" pii:"-"`
}
