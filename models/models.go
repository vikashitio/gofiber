package models

type Datas struct {
	MID   uint
	MName string
}

type LoginHistory struct {
	//gorm.Model
	Token_id    uint   `gorm:"primaryKey"`
	Client_id   uint   `json:"client_id,omitempty"`
	Login_time  string `json:"login_time,omitempty"`
	Logout_time string `json:"logout_time,omitempty"`
	Login_ip    string `json:"login_ip,omitempty"`
}

type LoginList struct {
	//gorm.Model
	Client_id uint `gorm:"primaryKey"`
	Full_name string
	Password  string
	Status    int
	Volt_id   string
}

type UpdateVolt struct {
	//gorm.Model
	Client_id uint `gorm:"primaryKey"`
	Volt_id   string
}

type Client_Master struct {
	//gorm.Model
	Client_id uint `gorm:"primaryKey"`
	Username  string
	Full_name string
	Password  string
	Status    int
}

type UserSession struct {
	LoginMerchantName   string
	LoginMerchantID     uint
	LoginMerchantEmail  string
	LoginMerchantStatus int
	Session             string             `json:"userSession"`
	Sessions            []UserSessionOther `json:"sessions"`
}
type UserSessionOther struct {
	LoginIP    string
	LoginTime  string
	LoginAgent string
}

type ApiBody struct {
	BodyData string
}

type VaultList struct {
	Id         int           `json:"id,omitempty"`
	Name       string        `json:"name,omitempty"`
	HiddenOnUI string        `json:"hiddenOnUI,omitempty"`
	AutoFuel   string        `json:"autoFuel,omitempty"`
	Assets     []AddressList `json:"assets"`
}

type AddressList struct {
	Id           string `json:"id,omitempty"`
	Total        string `json:"total,omitempty"`
	Balance      string `json:"balance,omitempty"`
	LockedAmount string `json:"lockedAmount,omitempty"`
	Available    string `json:"available,omitempty"`
	Pending      string `json:"pending,omitempty"`
	Frozen       string `json:"frozen,omitempty"`
	Staked       string `json:"staked,omitempty"`
	BlockHeight  string `json:"blockHeight,omitempty"`
}
type UserApi struct {
	ID        string `json:"id,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Role      string `json:"role,omitempty"`
	Email     string `json:"email,omitempty"`
	Enabled   string `json:"enabled,omitempty"`
}

// Define the struct for the nested reward info
type RewardInfo struct {
	PendingRewards string `json:"pendingRewards"`
}

// Define the struct for each asset
type Asset struct {
	ID           string      `json:"id"`
	Total        string      `json:"total"`
	Balance      string      `json:"balance"`
	LockedAmount string      `json:"lockedAmount"`
	Available    string      `json:"available"`
	Pending      string      `json:"pending"`
	Frozen       string      `json:"frozen"`
	Staked       string      `json:"staked"`
	BlockHeight  string      `json:"blockHeight"`
	RewardInfo   *RewardInfo `json:"rewardInfo,omitempty"`
}

// Define the main struct for the JSON response
type FireblocksResponse struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	HiddenOnUI bool    `json:"hiddenOnUI"`
	AutoFuel   bool    `json:"autoFuel"`
	Assets     []Asset `json:"assets"`
}

// Define the main struct for the JSON response
type FireblocksUsers struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Role      string `json:"role"`
	Email     string `json:"email,omitempty"`
	Enabled   bool   `json:"enabled"`
}

// Define the struct for each asset
type Address struct {
	AssetId           string `json:"assetId"`
	Address           string `json:"address"`
	Description       string `json:"description,omitempty"`
	Tag               string `json:"tag,omitempty"`
	Type              string `json:"type"`
	AddressFormat     string `json:"addressFormat"`
	LegacyAddress     string `json:"legacyAddress,omitempty"`
	EnterpriseAddress string `json:"enterpriseAddress,omitempty"`
	Bip44AddressIndex int    `json:"bip44AddressIndex"`
	UserDefined       bool   `json:"userDefined"`
}

// Define the main struct for the JSON response
type FireblocksAddress struct {
	Addresses []Address `json:"addresses"`
}

// Define the main struct for the JSON response
type FireblocksWallet struct {
	Id            int    `json:"id,omitempty"`
	Address       string `json:"address,omitempty"`
	LegacyAddress string `json:"legacyAddress,omitempty"`
	Tag           string `json:"tag,omitempty"`
	Message       string `json:"message,omitempty"`
	Code          int    `json:"code,omitempty"`
}
type CreateVaultAccountResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Profile struct {
	Client_id uint `gorm:"primaryKey"`
	//Title        string
	Gender       string
	BirthDate    string
	CountryCode  string
	Mobile       string
	AddressLine1 string
	AddressLine2 string
}
type Alert struct {
	Alert string
}
